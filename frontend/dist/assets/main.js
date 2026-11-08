/* Authenticator — 前端逻辑（调用 Wails Go 绑定） */
"use strict";

const app = window.go.main.App;

/* ---------- 图标（Material Icons path data） ---------- */
const ICONS = {
    copy: '<svg viewBox="0 0 24 24"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>',
    next: '<svg viewBox="0 0 24 24"><path d="M6 18l8.5-6L6 6v12zM16 6v12h2V6h-2z"/></svg>',
    edit: '<svg viewBox="0 0 24 24"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34a.9959.9959 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>',
    trash: '<svg viewBox="0 0 24 24"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>',
    export: '<svg viewBox="0 0 24 24"><path d="M9 16h6v-6h4l-7-7-7 7h4v6zm-4 2h14v2H5v-2z"/></svg>',
};

/* ---------- 全局状态 ---------- */
let entries = [];          // ListSecrets 结果缓存
let filterText = "";
let timerId = null;
let editingName = null;    // null = 添加模式
let pendingDeleteName = null;
let exportTarget = null;   // null = 全部导出, 字符串 = 单条导出
let importFilePath = null;
let autoSyncTimer = null;  // WebDAV 防抖自动同步

/* ---------- DOM 快捷 ---------- */
const $ = (id) => document.getElementById(id);

/* ---------- Snackbar ---------- */
let snackTimer = null;
function snackbar(msg) {
    const el = $("snackbar");
    el.textContent = msg;
    el.hidden = false; // 回退路径（无 Popover API 时仍按原方式显示）
    // 进入浏览器顶层显示，压过打开中的 <dialog>（含其遮罩）
    if (el.showPopover) {
        try { el.showPopover(); } catch (e) { /* 已在顶层时忽略 */ }
    }
    // 重新触发进入动画
    el.style.animation = "none";
    void el.offsetWidth;
    el.style.animation = "";
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => {
        if (el.hidePopover) {
            try { el.hidePopover(); } catch (e) { /* 未显示时忽略 */ }
        }
        el.hidden = true;
    }, 2600);
}

/* ---------- 主题（跟随系统，可手动覆盖） ---------- */
const mql = window.matchMedia("(prefers-color-scheme: dark)");

function applyTheme() {
    const saved = localStorage.getItem("tg-theme");
    const dark = saved ? saved === "dark" : mql.matches;
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    // 亮色时显示"暗月亮"图标，暗色时显示"亮太阳"
    $("theme-icon").innerHTML = dark
        ? '<path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zm2 5c0 1.1-.9 2-2 2s-2-.9-2-2 .9-2 2-2 2 .9 2 2zm0-11h-4v3h4V1zm0 20h-4v3h4v-3zM5.64 5.64L4.22 4.22 2.8 5.64l1.42 1.42 1.42-1.42zm12.72 12.72l1.42 1.42 1.42-1.42-1.42-1.42-1.42 1.42zM1 12v4h3v-4H1zm19 0v4h3v-4h-3zM5.64 18.36L4.22 19.78l1.42 1.42 1.42-1.42-1.42-1.42zm12.72-12.72l1.42-1.42-1.42-1.42-1.42 1.42 1.42 1.42z"/>'
        : '<path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/>';
}

$("btn-theme").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme === "dark";
    localStorage.setItem("tg-theme", dark ? "light" : "dark");
    applyTheme();
});

mql.addEventListener("change", () => {
    if (!localStorage.getItem("tg-theme")) applyTheme();
});

/* ============================================================
   解锁门
   ============================================================ */
let gateFirstRun = true; // 当前解锁门模式：true=首启设置密码，false=解锁
let fpAutoTried = false; // 本次解锁门展示是否已自动触发过指纹验证

// setupGateMode 检测保险库是否存在并切换解锁门模式（可重入：锁定回来后再走一次）
async function setupGateMode() {
    let exists = false;
    try {
        exists = await app.VaultExists();
    } catch (e) {
        $("gate-sub").textContent = "无法访问保险库：" + e;
        return;
    }
    gateFirstRun = !exists;
    $("gate-sub").textContent = gateFirstRun ? "首次使用，请设置主密码" : "输入主密码解锁保险库";
    $("gate-btn").textContent = gateFirstRun ? "设置主密码并创建保险库" : "解锁";
    $("gate-warn").hidden = !gateFirstRun;
    $("gate-pwd2-field").hidden = !gateFirstRun;

    // 指纹快速解锁（默认自动）：解锁门出现即自动弹出系统 Hello 验证，
    // 手指一按即进；取消弹窗则回退主密码输入，无需任何点击
    fpAutoTried = false;
    maybeAutoQuickUnlock();
}

// maybeAutoQuickUnlock 每次解锁门展示至多自动触发一次 Hello 验证
function maybeAutoQuickUnlock() {
    if (gateFirstRun || fpAutoTried) return;
    fpAutoTried = true;
    (async () => {
        try {
            const avail = await app.FingerprintUnlockAvailable();
            if (!avail) return;
            await app.QuickUnlock();
            if (!$("gate").hidden) enterMain(); // 期间未被密码解锁
        } catch (e) {
            const msg = String(e).replace(/^Error:\s*/i, "");
            if (msg === "已取消指纹验证" || !$("gate").hidden) return; // 取消/已解锁：静默回退密码
            $("gate-error").textContent = msg;
            $("gate-error").hidden = false;
        }
    })();
}

async function initGate() {
    await setupGateMode();
    $("gate-pwd-field").style.setProperty("margin-top", "20px");
    $("gate-pwd").focus();

    const submit = async () => {
        const pwd = $("gate-pwd").value;
        const errEl = $("gate-error");
        errEl.hidden = true;

        try {
            if (gateFirstRun) {
                if (!pwd) throw new Error("主密码不能为空");
                if (pwd !== $("gate-pwd2").value) throw new Error("两次输入的密码不一致");
                await app.SetPassword(pwd);
            } else {
                if (!pwd) throw new Error("请输入主密码");
                await app.Unlock(pwd);
            }
            enterMain();
        } catch (e) {
            errEl.textContent = String(e).replace(/^Error:\s*/i, "");
            errEl.hidden = false;
            const card = document.querySelector(".gate-card");
            card.classList.remove("shake");
            void card.offsetWidth;
            card.classList.add("shake");
            $("gate-pwd").select();
        }
    };

    $("gate-btn").addEventListener("click", submit);
    $("gate-pwd").addEventListener("keydown", (ev) => { if (ev.key === "Enter") submit(); });
    $("gate-pwd2").addEventListener("keydown", (ev) => { if (ev.key === "Enter") submit(); });
}

/* ============================================================
   主界面
   ============================================================ */
async function enterMain() {
    $("gate").hidden = true;
    $("main").hidden = false;
    await loadAndRender();
    startTimer();
}

async function backToGate() {
    stopTimer();
    app.Lock();
    $("main").hidden = true;
    $("gate").hidden = false;
    $("gate-pwd").value = "";
    $("gate-pwd2").value = "";
    $("gate-error").hidden = true;
    await setupGateMode(); // 重新检测：保险库此时必然已存在 → 解锁模式
    $("gate-pwd").focus();
}

/* ---------- 列表渲染 ---------- */
async function loadAndRender() {
    entries = await app.ListSecrets();
    renderList();
    updateStats();
}

function updateStats() {
    const n = entries.length;
    $("vault-stats").textContent = n === 0 ? "空空如也" : `${n} 个密钥 · 已解锁`;
}

function currentEntries() {
    const q = filterText.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter((e) => e.name.toLowerCase().includes(q));
}

function renderList() {
    const list = $("list");
    list.innerHTML = "";
    const visible = currentEntries();

    $("empty-state").hidden = entries.length !== 0 || filterText.trim() !== "";
    $("empty-state").classList.toggle("empty", true);

    if (entries.length !== 0 && visible.length === 0) {
        const p = document.createElement("p");
        p.className = "empty-sub";
        p.style.cssText = "text-align:center;margin:24px auto;max-width:720px;";
        p.textContent = `没有匹配「${filterText.trim()}」的密钥`;
        list.appendChild(p);
        return;
    }

    visible.forEach((e, i) => {
        const card = buildCard(e);
        card.style.animationDelay = `${Math.min(i * 30, 300)}ms`;
        list.appendChild(card);
    });
}

function buildCard(e) {
    const card = document.createElement("article");
    card.className = "card";
    card.dataset.name = e.name;

    const isHOTP = e.algo === "HOTP";
    card.innerHTML = `
        <div class="card-main">
            <div class="card-info">
                <h2 class="card-name"></h2>
                <div class="card-chips">
                    <span class="chip ${isHOTP ? "chip-hotp" : "chip-totp"}">${e.algo}</span>
                    ${isHOTP ? '<span class="chip chip-counter" data-role="counter"></span>' : ""}
                </div>
            </div>
            <div class="card-code">
                ${isHOTP
                    ? '<span class="card-hotp-meta" data-role="hotp-meta"></span>'
                    : `<svg class="ring" data-role="ring" viewBox="0 0 40 40">
                        <circle class="ring-track" cx="20" cy="20" r="15"></circle>
                        <circle class="ring-bar" data-role="ring-bar" cx="20" cy="20" r="15"
                            stroke-dasharray="94.25" stroke-dashoffset="0"></circle>
                    </svg>`}
                <span class="code" data-role="code">······</span>
            </div>
        </div>
        <div class="card-actions">
            <button class="btn btn-tonal" data-action="copy">
                ${ICONS.copy}<span data-role="copy-label">复制</span>
            </button>
            ${isHOTP ? `<button class="btn btn-outlined" data-action="next">${ICONS.next}<span>下一个</span></button>` : ""}
            <span class="spacer"></span>
            <button class="icon-btn" data-action="edit" title="查看 / 编辑">${ICONS.edit}</button>
            <button class="icon-btn" data-action="export" title="导出该密钥">${ICONS.export}</button>
            <button class="icon-btn icon-btn-danger" data-action="delete" title="删除">${ICONS.trash}</button>
        </div>`;

    card.querySelector(".card-name").textContent = e.name;

    card.querySelector('[data-action="copy"]').addEventListener("click", () => copyCode(card));
    card.querySelector('[data-action="edit"]').addEventListener("click", () => openEntryDialog(e.name));
    card.querySelector('[data-action="export"]').addEventListener("click", () => openExportDialog(e.name));
    card.querySelector('[data-action="delete"]').addEventListener("click", () => openConfirmDialog(e.name));
    if (isHOTP) card.querySelector('[data-action="next"]').addEventListener("click", () => hotpNext(card, e.name));

    return card;
}

/* ---------- 每秒刷新验证码 ---------- */
function startTimer() {
    stopTimer();
    tick();
    timerId = setInterval(tick, 1000);
}

function stopTimer() {
    if (timerId) { clearInterval(timerId); timerId = null; }
}

async function tick() {
    let snapshot;
    try {
        snapshot = await app.GetSnapshot();
    } catch (e) {
        backToGate();
        return;
    }
    if (!snapshot) return;

    const byName = new Map(snapshot.map((s) => [s.name, s]));
    for (const card of document.querySelectorAll(".card")) {
        const s = byName.get(card.dataset.name);
        if (!s) continue; // 被搜索过滤掉的卡片
        const codeEl = card.querySelector('[data-role="code"]');

        if (s.error) {
            codeEl.textContent = s.error;
            codeEl.classList.add("code-invalid");
            continue;
        }
        codeEl.classList.remove("code-invalid");
        codeEl.textContent = s.code;

        if (s.secondsRemaining >= 0) {
            const bar = card.querySelector('[data-role="ring-bar"]');
            if (bar) {
                bar.setAttribute("stroke-dashoffset", (94.25 * (1 - s.secondsRemaining / 30)).toFixed(2));
                bar.classList.toggle("urgent", s.secondsRemaining <= 5);
                codeEl.classList.toggle("code-expiring", s.secondsRemaining <= 5);
            }
        } else if (s.algo === "HOTP") {
            const cnt = card.querySelector('[data-role="counter"]');
            const meta = card.querySelector('[data-role="hotp-meta"]');
            if (cnt) cnt.textContent = `计数 ${s.counter}`;
            if (meta) meta.textContent = `计数 ${s.counter}`;
        }
    }
}

/* ---------- 复制验证码 ---------- */
async function copyCode(card) {
    const codeEl = card.querySelector('[data-role="code"]');
    const code = codeEl.textContent;
    if (!code || code === "······") return;

    try {
        await navigator.clipboard.writeText(code);
    } catch (e) {
        snackbar("复制失败：" + e);
        return;
    }

    const btn = card.querySelector('[data-action="copy"]');
    const label = btn.querySelector('[data-role="copy-label"]');
    btn.classList.add("btn-copied");
    label.textContent = "已复制";
    btn.querySelector("svg").outerHTML = ICONS.check;
    snackbar(`验证码 ${code} 已复制到剪贴板`);

    setTimeout(() => {
        btn.classList.remove("btn-copied");
        label.textContent = "复制";
        btn.querySelector("svg").outerHTML = ICONS.copy;
    }, 1800);
}

/* ---------- HOTP 下一个 ---------- */
async function hotpNext(card, name) {
    try {
        await app.NextHOTP(name);
        card.classList.add("flash");
        setTimeout(() => card.classList.remove("flash"), 400);
        await tick();
        scheduleAutoSync();
    } catch (e) {
        snackbar(String(e).replace(/^Error:\s*/i, ""));
    }
}

/* ============================================================
   添加 / 编辑对话框
   ============================================================ */
const dlgEntry = $("dlg-entry");

function setAlgo(algo) {
    document.querySelectorAll("#seg-algo .seg-btn").forEach((b) => {
        b.classList.toggle("seg-checked", b.dataset.value === algo);
    });
    $("entry-counter-field").hidden = algo !== "HOTP";
}

function currentAlgo() {
    return document.querySelector("#seg-algo .seg-checked").dataset.value;
}

document.querySelectorAll("#seg-algo .seg-btn").forEach((b) => {
    b.addEventListener("click", () => setAlgo(b.dataset.value));
});

async function openEntryDialog(name) {
    editingName = name;
    $("entry-dialog-title").textContent = name ? "编辑密钥" : "添加密钥";
    $("entry-error").hidden = true;
    $("entry-name").value = "";
    $("entry-secret").value = "";
    $("entry-counter").value = "0";
    setAlgo("TOTP");

    if (name) {
        try {
            const full = await app.GetEntry(name);
            $("entry-name").value = full.name;
            $("entry-secret").value = full.secret;
            $("entry-counter").value = String(full.counter);
            setAlgo(full.algo);
        } catch (e) {
            snackbar(String(e).replace(/^Error:\s*/i, ""));
            return;
        }
    }
    dlgEntry.showModal();
    $("entry-name").focus();
}

async function saveEntry() {
    const name = $("entry-name").value.trim();
    const secret = $("entry-secret").value.trim();
    const algo = currentAlgo();
    const counter = Math.max(0, parseInt($("entry-counter").value, 10) || 0);
    const errEl = $("entry-error");
    errEl.hidden = true;

    const fail = (msg) => { errEl.textContent = msg; errEl.hidden = false; };

    if (!name) return fail("密钥名称不能为空");
    if (!secret) return fail("Base32 密钥不能为空");

    try {
        if (editingName) {
            await app.UpdateSecret(editingName, name, secret, algo, counter);
            snackbar(`已更新 ${algo} 密钥：${name}`);
        } else {
            await app.AddSecret(name, secret, algo, counter);
            snackbar(`已添加 ${algo} 密钥：${name}`);
        }
        dlgEntry.close();
        await loadAndRender();
        await tick();
        scheduleAutoSync();
    } catch (e) {
        fail(String(e).replace(/^Error:\s*/i, ""));
    }
}

$("entry-save").addEventListener("click", saveEntry);
$("entry-cancel").addEventListener("click", () => dlgEntry.close());
$("entry-secret").addEventListener("keydown", (ev) => { if (ev.key === "Enter") saveEntry(); });
$("entry-name").addEventListener("keydown", (ev) => { if (ev.key === "Enter") $("entry-secret").focus(); });
$("fab").addEventListener("click", () => openEntryDialog(null));
$("empty-add").addEventListener("click", () => openEntryDialog(null));

/* ============================================================
   通用确认对话框（删除密钥 / 停用同步等）
   ============================================================ */
const dlgConfirm = $("dlg-confirm");
let confirmAction = null; // 点击确认按钮后执行的回调

// askConfirm 弹出通用确认框，action 在确认后执行
function askConfirm(title, body, okLabel, action) {
    $("confirm-title").textContent = title;
    $("confirm-body").textContent = body;
    $("confirm-ok").textContent = okLabel;
    confirmAction = action;
    dlgConfirm.showModal();
}

$("confirm-ok").addEventListener("click", async () => {
    const action = confirmAction;
    confirmAction = null;
    dlgConfirm.close();
    if (action) await action();
});
$("confirm-cancel").addEventListener("click", () => dlgConfirm.close());

// openConfirmDialog 删除密钥的确认流程
function openConfirmDialog(name) {
    pendingDeleteName = name;
    askConfirm("删除密钥？", `确定要删除密钥「${name}」吗？此操作无法撤销。`, "删除", async () => {
        try {
            await app.RemoveSecret(name);
            snackbar(`已删除密钥：${name}`);
        } catch (e) {
            snackbar(String(e).replace(/^Error:\s*/i, ""));
        }
        await loadAndRender();
        scheduleAutoSync();
    });
}

/* ============================================================
   导出（全部 / 单条）
   ============================================================ */
const dlgExport = $("dlg-export");

function openExportDialog(name) {
    exportTarget = name || null;
    $("export-title").textContent = name ? `导出密钥「${name}」` : "导出全部密钥";
    $("export-scope").textContent = name
        ? "将为该密钥生成独立的加密导出文件。"
        : "将全部密钥导出为加密备份文件（含算法与计数器）。";
    $("export-pwd").value = "";
    $("export-error").hidden = true;
    dlgExport.showModal();
    $("export-pwd").focus();
}

$("export-ok").addEventListener("click", async () => {
    const pwd = $("export-pwd").value;
    const errEl = $("export-error");
    errEl.hidden = true;
    if (!pwd) { errEl.textContent = "请输入导出文件密码"; errEl.hidden = false; return; }

    const path = await app.PickSaveFile("选择导出位置", "Authenticator-export.enc");
    if (!path) return; // 用户取消

    try {
        if (exportTarget) {
            await app.ExportSingle(exportTarget, path, pwd);
            snackbar(`已导出「${exportTarget}」`);
        } else {
            await app.ExportVault(path, pwd);
            snackbar("全部密钥已导出");
        }
        dlgExport.close();
    } catch (e) {
        errEl.textContent = String(e).replace(/^Error:\s*/i, "");
        errEl.hidden = false;
    }
});
$("export-cancel").addEventListener("click", () => dlgExport.close());
$("btn-export").addEventListener("click", () => openExportDialog(null));

/* ============================================================
   导入
   ============================================================ */
const dlgImport = $("dlg-import");

$("btn-import").addEventListener("click", async () => {
    const path = await app.PickOpenFile("选择要导入的加密文件");
    if (!path) return;
    importFilePath = path;
    $("import-file").textContent = "已选择文件：" + path.split(/[\\/]/).pop();
    $("import-pwd").value = "";
    $("import-error").hidden = true;
    dlgImport.showModal();
    $("import-pwd").focus();
});

$("import-ok").addEventListener("click", async () => {
    const pwd = $("import-pwd").value;
    const errEl = $("import-error");
    errEl.hidden = true;
    if (!pwd) { errEl.textContent = "请输入导出文件密码"; errEl.hidden = false; return; }

    try {
        const n = await app.ImportVault(importFilePath, pwd);
        dlgImport.close();
        snackbar(n > 0 ? `成功导入 ${n} 条密钥` : "没有新密钥可导入（全部重名或无效）");
        await loadAndRender();
        await tick();
        scheduleAutoSync();
    } catch (e) {
        errEl.textContent = String(e).replace(/^Error:\s*/i, "");
        errEl.hidden = false;
    }
});
$("import-cancel").addEventListener("click", () => dlgImport.close());

/* ============================================================
   WebDAV 同步
   ============================================================ */
const dlgSync = $("dlg-sync");

$("btn-sync").addEventListener("click", async () => {
    let s;
    try {
        s = await app.GetSyncSettings();
    } catch (e) {
        snackbar(String(e).replace(/^Error:\s*/i, ""));
        return;
    }
    if (s.configured) {
        runSyncNow();
    } else {
        openSyncDialog();
    }
});

function syncBtnBusy(busy) {
    const btn = $("btn-sync");
    btn.classList.toggle("spinning", busy);
    btn.title = busy ? "同步中…" : "WebDAV 同步（点击立即同步 · 右键详情）";
}

async function runSyncNow() {
    if ($("btn-sync").classList.contains("spinning")) return; // 已在同步中
    syncBtnBusy(true);
    try {
        const r = await app.SyncNow();
        const parts = [];
        if (r.added) parts.push(`新增 ${r.added}`);
        if (r.updated) parts.push(`更新 ${r.updated}`);
        if (r.deleted) parts.push(`删除 ${r.deleted}`);
        snackbar(parts.length ? `同步完成：${parts.join(" · ")}` : "已与云端一致");
        await loadAndRender();
        await tick();
    } catch (e) {
        snackbar(String(e).replace(/^Error:\s*/i, ""));
    } finally {
        syncBtnBusy(false);
    }
}

// scheduleAutoSync 数据变更后防抖 2.5s 静默同步（失败仅记录在后端，不打扰用户）
function scheduleAutoSync() {
    clearTimeout(autoSyncTimer);
    autoSyncTimer = setTimeout(async () => {
        try {
            const s = await app.GetSyncSettings();
            if (!s.configured) return;
            await app.SyncNow();
            await loadAndRender();
            await tick();
        } catch (e) {
            console.warn("自动同步失败:", e);
        }
    }, 2500);
}

async function openSyncDialog() {
    let s;
    try {
        s = await app.GetSyncSettings();
    } catch (e) {
        s = {};
    }
    $("sync-last").textContent = s.lastSyncError
        ? "上次同步失败：" + s.lastSyncError
        : (s.lastSyncText ? "上次同步：" + s.lastSyncText : "尚未同步过");
    $("sync-server").value = s.serverUrl || "";
    $("sync-user").value = s.username || "";
    $("sync-webdav-pwd").value = ""; // 不回传密码，留空 = 沿用已保存的值
    $("sync-path").value = s.remotePath || "Authenticator/sync.enc";
    $("sync-pwd").value = "";
    $("sync-error").hidden = true;
    dlgSync.showModal();
    $("sync-server").focus();
}

function showSyncError(msg) {
    const el = $("sync-error");
    el.textContent = msg;
    el.hidden = !msg;
}

async function testSyncConnection() {
    const btn = $("sync-test");
    const server = $("sync-server").value.trim();
    if (!server) { showSyncError("请先填写服务器地址"); return; }
    btn.disabled = true;
    btn.textContent = "测试中…";
    try {
        await app.TestSyncConnection(server, $("sync-user").value.trim(), $("sync-webdav-pwd").value);
        $("sync-error").hidden = true;
        snackbar("连接成功");
    } catch (e) {
        showSyncError(String(e).replace(/^Error:\s*/i, ""));
    } finally {
        btn.disabled = false;
        btn.textContent = "测试连接";
    }
}

async function saveSyncSettings() {
    const server = $("sync-server").value.trim();
    if (!server) return showSyncError("服务器地址不能为空");

    const btn = $("sync-save");
    btn.disabled = true;
    btn.textContent = "保存中…";
    try {
        await app.SaveSyncSettings(
            server,
            $("sync-user").value.trim(),
            $("sync-webdav-pwd").value,
            $("sync-path").value.trim(),
            $("sync-pwd").value,
        );
        dlgSync.close();
        snackbar("同步配置已保存");
        await runSyncNow(); // 保存成功后立即推送一次
    } catch (e) {
        showSyncError(String(e).replace(/^Error:\s*/i, ""));
    } finally {
        btn.disabled = false;
        btn.textContent = "保存并启用";
    }
}

$("sync-test").addEventListener("click", testSyncConnection);
$("sync-save").addEventListener("click", saveSyncSettings);
$("sync-cancel").addEventListener("click", () => dlgSync.close());

/* ---------- 同步详情（右键同步按钮打开） ---------- */
const dlgSyncInfo = $("dlg-sync-info");

$("btn-sync").addEventListener("contextmenu", (ev) => {
    ev.preventDefault();
    openSyncInfo();
});

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

async function openSyncInfo() {
    let s;
    try {
        s = await app.GetSyncSettings();
    } catch (e) {
        s = {};
    }
    $("sync-info-status").textContent = s.configured ? "已启用" : "未配置";
    $("sync-info-server").textContent = s.serverUrl || "—";
    $("sync-info-user").textContent = s.username || "（匿名）";
    $("sync-info-path").textContent = s.remotePath || "—";

    const last = [];
    if (s.lastSyncAt) last.push(s.lastSyncAt);
    if (s.lastSyncError) last.push("失败：" + s.lastSyncError);
    else if (s.lastSyncText) last.push(s.lastSyncText);
    $("sync-info-last").textContent = last.length ? last.join(" · ") : "尚未同步";

    const errEl = $("sync-info-error");
    errEl.hidden = true;
    $("sync-info-remote").textContent = "查询中…";
    dlgSyncInfo.showModal();

    if (!s.configured) {
        $("sync-info-remote").textContent = "—";
        return;
    }
    try {
        const r = await app.GetSyncRemoteInfo();
        if (r.exists) {
            const at = r.modTime ? new Date(r.modTime).toLocaleString() : "";
            $("sync-info-remote").textContent =
                `已存在 · ${formatSize(r.size)}` + (at ? ` · 服务器时间 ${at}` : "");
        } else {
            $("sync-info-remote").textContent = "尚未上传（首次同步时创建）";
        }
    } catch (e) {
        $("sync-info-remote").textContent = "查询失败";
        errEl.textContent = String(e).replace(/^Error:\s*/i, "");
        errEl.hidden = false;
    }
}

$("sync-info-sync").addEventListener("click", async () => {
    dlgSyncInfo.close();
    await runSyncNow();
});

$("sync-info-edit").addEventListener("click", () => {
    dlgSyncInfo.close();
    openSyncDialog(); // 预填当前配置，改服务器地址即可更换
});

// 停用同步：二次确认后删除本地配置（云端文件不受影响）
$("sync-info-disable").addEventListener("click", () => {
    askConfirm(
        "停用 WebDAV 同步？",
        "将删除本地保存的同步配置（含服务器地址与应用密码）。云端文件不受影响，可随时重新配置。",
        "停用",
        async () => {
            try {
                await app.DisableSync();
                snackbar("已停用 WebDAV 同步");
            } catch (e) {
                snackbar(String(e).replace(/^Error:\s*/i, ""));
            }
        },
    );
});

/* ---------- 锁定 / 搜索 / 点击遮罩关闭对话框 ---------- */
$("btn-lock").addEventListener("click", backToGate);

/* ---------- 关于 ---------- */
const dlgAbout = $("dlg-about");
$("btn-about").addEventListener("click", () => dlgAbout.showModal());
$("about-close").addEventListener("click", () => dlgAbout.close());

$("search").addEventListener("input", (ev) => {
    filterText = ev.target.value;
    renderList();
});

document.querySelectorAll("dialog").forEach((d) => {
    d.addEventListener("click", (ev) => {
        if (ev.target === d) d.close(); // 点击遮罩关闭
    });
});

/* ---------- 启动 ---------- */
applyTheme();
initGate();
