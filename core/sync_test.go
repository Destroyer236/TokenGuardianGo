package core

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/webdav"
)

const testSecret2 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// mkEntry 构造固定时间戳的测试条目（保证 LWW 判定确定性）。
func mkEntry(name, secret, algo string, at time.Time) Entry {
	return Entry{Name: name, Secret: secret, Algo: algo, UpdatedAt: at}
}

// bumpEntry 将指定条目的 UpdatedAt 前进 d（测试辅助：跨设备场景构造确定的新旧关系，
// 规避 Windows 时钟粒度导致的并列时间戳）。
func bumpEntry(t *testing.T, v *Vault, name string, d time.Duration) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.entries {
		if v.entries[i].Name == name {
			v.entries[i].UpdatedAt = v.entries[i].UpdatedAt.Add(d)
			if err := v.save(); err != nil {
				t.Fatalf("bumpEntry save: %v", err)
			}
			return
		}
	}
	t.Fatalf("bumpEntry: 找不到 %s", name)
}

// bumpTombstone 将指定墓碑的 UpdatedAt 前进 d（测试辅助）。
func bumpTombstone(t *testing.T, v *Vault, name string, d time.Duration) {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.deleted {
		if v.deleted[i].Name == name {
			v.deleted[i].UpdatedAt = v.deleted[i].UpdatedAt.Add(d)
			if err := v.save(); err != nil {
				t.Fatalf("bumpTombstone save: %v", err)
			}
			return
		}
	}
	t.Fatalf("bumpTombstone: 找不到 %s", name)
}

// TestMergeRemoteEntries 远端条目的增/改/不动/并列四种走向。
func TestMergeRemoteEntries(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := v.Add("Local", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	// 统一本地时间戳，便于精确控制新旧关系
	v.mu.Lock()
	for i := range v.entries {
		v.entries[i].UpdatedAt = base
	}
	v.mu.Unlock()

	res, err := v.MergeFrom([]Entry{
		mkEntry("RemoteNew", testSecret, AlgoTOTP, base), // 本地不存在 → 新增
		mkEntry("Local", testSecret2, AlgoTOTP, base.Add(-time.Hour)), // 远端更旧 → 保留本地
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 || res.Updated != 0 || res.Deleted != 0 {
		t.Fatalf("远端旧条目合并结果 = %+v, 期望 Added=1", res)
	}
	e, _ := v.Get("Local")
	if e.Secret != testSecret {
		t.Error("远端更旧时本地条目应保持不变")
	}

	// 远端更新 → 覆盖本地
	res, err = v.MergeFrom([]Entry{
		mkEntry("Local", testSecret2, AlgoTOTP, base.Add(time.Hour)),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 1 {
		t.Fatalf("远端更新应 Updated=1, got %+v", res)
	}
	e, _ = v.Get("Local")
	if e.Secret != testSecret2 {
		t.Error("远端更新时应采用远端内容")
	}

	// 时间并列 → 保留本地
	res, err = v.MergeFrom([]Entry{
		mkEntry("Local", testSecret, AlgoTOTP, base.Add(time.Hour)), // 同一时刻
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated != 0 {
		t.Fatalf("并列时间应保留本地, got %+v", res)
	}
	e, _ = v.Get("Local")
	if e.Secret != testSecret2 {
		t.Error("并列时间时本地内容应保持不变")
	}
}

// TestMergeTombstones 墓碑的删除传播、复活与过期清除。
func TestMergeTombstones(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	v.mu.Lock()
	v.entries = []Entry{
		mkEntry("Gone", testSecret, AlgoTOTP, base),         // 将被远端墓碑删除
		mkEntry("Alive", testSecret, AlgoTOTP, base.Add(2*time.Hour)), // 比远端墓碑新 → 复活
	}
	v.mu.Unlock()

	res, err := v.MergeFrom(
		[]Entry{mkEntry("Alive", testSecret2, AlgoTOTP, base.Add(time.Hour))}, // 比本地旧、比墓碑新
		[]Entry{mkEntry("Gone", "", "", base.Add(time.Hour)), mkEntry("Alive", "", "", base.Add(time.Hour))},
	)
	if err != nil {
		t.Fatal(err)
	}
	// Gone：远端墓碑(base+1h) > 本地条目(base) → 删除传播
	// Alive：远端条目(base+1h) 比本地(base+2h) 旧 → 不动；远端墓碑(base+1h) 比本地条目旧 → 不删
	if res.Deleted != 1 {
		t.Fatalf("墓碑应传播删除 1 条, got %+v", res)
	}
	if _, err := v.Get("Gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Gone 应已被墓碑删除, got %v", err)
	}
	if _, err := v.Get("Alive"); err != nil {
		t.Errorf("Alive 不应被旧墓碑删除: %v", err)
	}
	if e, _ := v.Get("Alive"); e.Secret != testSecret {
		t.Errorf("Alive 应保持本地内容, got %+v", e)
	}
	if n := len(v.Deleted()); n != 1 {
		t.Fatalf("墓碑数 = %d, 期望 1（仅 Gone）", n)
	}

	// 复活：本地已删（有墓碑），远端条目比墓碑新 → 恢复并清除过期墓碑
	res, err = v.MergeFrom(
		[]Entry{mkEntry("Gone", testSecret, AlgoTOTP, base.Add(3*time.Hour))},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("复活应记为新增, got %+v", res)
	}
	if _, err := v.Get("Gone"); err != nil {
		t.Errorf("复活后应能取回 Gone: %v", err)
	}
	if n := len(v.Deleted()); n != 0 {
		t.Fatalf("复活后过期墓碑应被清除, 墓碑数 = %d", n)
	}
}

// TestMergeInvalidRemoteSkipped 远端非法条目（空名 / 坏算法 / 坏 Base32）必须跳过。
func TestMergeInvalidRemoteSkipped(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	res, err := v.MergeFrom([]Entry{
		mkEntry("", testSecret, AlgoTOTP, base),
		mkEntry("BadAlgo", testSecret, "MD5", base),
		mkEntry("BadB32", "not@base32!!", AlgoTOTP, base),
		mkEntry("Good", testSecret, AlgoTOTP, base),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("仅 1 条合法条目应被并入, got %+v", res)
	}
	if _, err := v.Get("Good"); err != nil {
		t.Errorf("合法条目应存在: %v", err)
	}
}

// TestVaultRemoveTombstone 删除产生墓碑并在重开后保留。
func TestVaultRemoveTombstone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := newTestVault(t, dir)
	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Remove("GitHub"); err != nil {
		t.Fatal(err)
	}
	if len(v.Deleted()) != 1 || v.Deleted()[0].Name != "GitHub" {
		t.Fatalf("删除后应有 GitHub 墓碑: %+v", v.Deleted())
	}
	v.Close()

	v2, err := Open(path, vaultPwd)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if len(v2.Deleted()) != 1 || v2.Deleted()[0].Name != "GitHub" {
		t.Fatalf("重开后墓碑应保留: %+v", v2.Deleted())
	}
}

// TestRemoveLocalOnlyNotSynced 本地删除不写入同步负载，但本机保持删除状态、不被远端复活。
func TestRemoveLocalOnlyNotSynced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	v := newTestVault(t, dir)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveLocalOnly("GitHub"); err != nil {
		t.Fatal(err)
	}
	if len(v.Deleted()) != 1 || !v.Deleted()[0].LocalOnly {
		t.Fatalf("应记录本地墓碑: %+v", v.Deleted())
	}

	// 同步负载不包含本地墓碑（远端不会看到这条删除）
	plain, err := v.syncPayload()
	if err != nil {
		t.Fatal(err)
	}
	var p vaultPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 || len(p.Deleted) != 0 {
		t.Fatalf("同步负载应为空（本地墓碑不上传）: entries=%d deleted=%d", len(p.Entries), len(p.Deleted))
	}
	v.Close()

	// 重开后墓碑仍在（本地保持删除状态）
	v2, err := Open(path, vaultPwd)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if len(v2.Deleted()) != 1 || !v2.Deleted()[0].LocalOnly {
		t.Fatalf("重开后本地墓碑应保留: %+v", v2.Deleted())
	}

	// 云端仍是旧状态（条目还在、无墓碑）→ 合并后本机依旧保持删除
	if _, err := v2.MergeFrom(
		[]Entry{mkEntry("GitHub", testSecret, AlgoTOTP, base)},
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := v2.Get("GitHub"); !errors.Is(err, ErrNotFound) {
		t.Errorf("本地墓碑应遮蔽远端条目，GitHub 不应复活: %v", err)
	}
	if len(v2.Deleted()) != 1 || !v2.Deleted()[0].LocalOnly {
		t.Fatalf("合并后应保持本地墓碑标记: %+v", v2.Deleted())
	}
}

// TestMergeLocalOnlyTombstoneStamp 本地较新的"仅本地删除"墓碑不被远端旧墓碑升级为可同步墓碑；
// 远端较新的墓碑胜出时按可同步处理。
func TestMergeLocalOnlyTombstoneStamp(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	v.mu.Lock()
	v.deleted = []Entry{{Name: "A", UpdatedAt: base.Add(2 * time.Hour), LocalOnly: true}}
	v.mu.Unlock()

	// 远端墓碑较旧 → 本地胜出，保持 LocalOnly
	if _, err := v.MergeFrom(nil, []Entry{mkEntry("A", "", "", base.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if len(v.Deleted()) != 1 || !v.Deleted()[0].LocalOnly {
		t.Fatalf("本地较新的墓碑应保持 LocalOnly: %+v", v.Deleted())
	}

	// 远端墓碑较新 → 覆盖为可同步墓碑（另一台设备重新删除的传播）
	if _, err := v.MergeFrom(nil, []Entry{mkEntry("A", "", "", base.Add(3*time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if len(v.Deleted()) != 1 || v.Deleted()[0].LocalOnly {
		t.Fatalf("远端较新的墓碑应为可同步墓碑: %+v", v.Deleted())
	}
}

// TestReAddClearsLocalOnlyTombstone 本地删除后重建同名密钥：墓碑清除、条目重新进入同步负载。
func TestReAddClearsLocalOnlyTombstone(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	if err := v.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveLocalOnly("GitHub"); err != nil {
		t.Fatal(err)
	}
	if err := v.Add("GitHub", testSecret2, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if n := len(v.Deleted()); n != 0 {
		t.Fatalf("重建同名密钥后墓碑应清除, 墓碑数 = %d", n)
	}
	plain, err := v.syncPayload()
	if err != nil {
		t.Fatal(err)
	}
	var p vaultPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 || p.Entries[0].Name != "GitHub" || p.Entries[0].Secret != testSecret2 {
		t.Fatalf("同步负载应含重建的 GitHub: %+v", p.Entries)
	}
}

// TestImportTombstoneOnlyFile 导入只含墓碑的同步文件：导入 0 条并明确标记，而不是笼统报"重名或无效"。
func TestImportTombstoneOnlyFile(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	defer v.Close()

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(vaultPayload{
		Deleted: []Entry{{Name: "Gone", UpdatedAt: time.Now()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	syncFile := filepath.Join(dir, "sync.enc")
	blob, err := encryptBlob(plain, deriveKey("sync-pwd", salt), salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeVaultFile(syncFile, blob); err != nil {
		t.Fatal(err)
	}

	res, err := v.Import(syncFile, "sync-pwd")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 0 || !res.TombstoneOnly {
		t.Fatalf("应识别为纯墓碑同步文件, got %+v", res)
	}
}

// TestVaultOldFormatWithoutTombstones 旧版保险库文件（无 deleted 字段）必须能正常打开并继续写入。
func TestVaultOldFormatWithoutTombstones(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")

	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(vaultPayload{Entries: []Entry{mkEntry("Old", testSecret, AlgoTOTP, base)}})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := encryptBlob(plain, deriveKey(vaultPwd, salt), salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	v, err := Open(path, vaultPwd)
	if err != nil {
		t.Fatalf("旧格式应能打开: %v", err)
	}
	defer v.Close()
	if len(v.Entries()) != 1 || len(v.Deleted()) != 0 {
		t.Fatalf("旧格式解析不符: entries=%d deleted=%d", len(v.Entries()), len(v.Deleted()))
	}
	if err := v.Add("New", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatalf("旧格式打开后应可继续写入: %v", err)
	}
	v.Close()

	v2, err := Open(path, vaultPwd)
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	defer v2.Close()
	if len(v2.Entries()) != 2 {
		t.Fatalf("重新打开后条目数 = %d, 期望 2", len(v2.Entries()))
	}
}

// TestSyncConfigRoundTrip 配置保存 → 重开保险库 → 读取一致；错误保险库密钥拒绝解密。
func TestSyncConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v := newTestVault(t, dir)
	cfgPath := SyncConfigPath(filepath.Join(dir, "vault.enc"))

	cfg := &SyncConfig{
		ServerURL:      "https://dav.example.com/dav/",
		Username:       "user@example.com",
		WebDAVPassword: "app-password",
		SyncPassword:   "sync-pass",
		RemotePath:     "Authenticator/sync.enc",
	}
	if err := SaveSyncConfig(cfgPath, v, cfg); err != nil {
		t.Fatalf("SaveSyncConfig: %v", err)
	}
	v.Close()

	// 同一主密码重开（盐一致 → 派生密钥一致）
	v2, err := Open(filepath.Join(dir, "vault.enc"), vaultPwd)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()

	got, err := LoadSyncConfig(cfgPath, v2)
	if err != nil {
		t.Fatalf("LoadSyncConfig: %v", err)
	}
	if got == nil {
		t.Fatal("配置应存在")
	}
	if got.ServerURL != "https://dav.example.com/dav" { // Normalize 去尾斜杠
		t.Errorf("ServerURL = %q", got.ServerURL)
	}
	if got.Username != cfg.Username || got.WebDAVPassword != cfg.WebDAVPassword ||
		got.SyncPassword != cfg.SyncPassword || got.RemotePath != cfg.RemotePath {
		t.Errorf("配置不一致: got %+v", got)
	}

	// 不同主密码的保险库（不同派生密钥）应无法解密
	v3, err := Create(filepath.Join(dir, "other.enc"), "other-password")
	if err != nil {
		t.Fatal(err)
	}
	defer v3.Close()
	if _, err := LoadSyncConfig(cfgPath, v3); err == nil {
		t.Fatal("错误保险库密钥应拒绝解密配置")
	}

	// 未配置 → (nil, nil)
	got, err = LoadSyncConfig(filepath.Join(dir, "missing.enc"), v2)
	if err != nil || got != nil {
		t.Fatalf("不存在的配置应返回 (nil, nil), got (%+v, %v)", got, err)
	}
}

// TestSyncConfigValidate 配置校验规则。
func TestSyncConfigValidate(t *testing.T) {
	valid := SyncConfig{ServerURL: "https://dav.jianguoyun.com/dav/", SyncPassword: "p", RemotePath: "a/b.enc"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("合法配置不应报错: %v", err)
	}
	cases := []SyncConfig{
		{ServerURL: "", SyncPassword: "p"},
		{ServerURL: "ftp://x", SyncPassword: "p"},
		{ServerURL: "https://x", SyncPassword: ""},
		{ServerURL: "https://x", SyncPassword: "p", RemotePath: "../escape.enc"},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d 应报错: %+v", i, c)
		}
	}
	// 空路径 Normalize 后用默认值
	c := SyncConfig{ServerURL: "https://x", SyncPassword: "p"}
	c.Normalize()
	if c.RemotePath != DefaultRemotePath {
		t.Errorf("空路径应取默认值, got %q", c.RemotePath)
	}
}

// newWebDAVTestServer 起一个进程内真实 WebDAV 服务（httptest + x/net/webdav）。
func newWebDAVTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(&webdav.Handler{
		FileSystem: webdav.Dir(t.TempDir()),
		LockSystem: webdav.NewMemLS(),
	})
	t.Cleanup(srv.Close)
	return srv
}

// TestDoSyncEndToEnd 双设备经真实 WebDAV 服务收敛：新增传播、修改传播、删除传播、
// 收敛一致、同步密码错误被拒。
func TestDoSyncEndToEnd(t *testing.T) {
	srv := newWebDAVTestServer(t)
	cfg := &SyncConfig{
		ServerURL:      srv.URL,
		Username:       "user",
		WebDAVPassword: "pass",
		SyncPassword:   "sync-pass",
		RemotePath:     "Authenticator/sync.enc",
	}

	// 两台设备：不同主密码、独立保险库（同步密码是唯一的纽带）
	vA := newTestVault(t, t.TempDir())
	defer vA.Close()
	vB, err := Create(filepath.Join(t.TempDir(), "vault.enc"), "pwd-B")
	if err != nil {
		t.Fatal(err)
	}
	defer vB.Close()

	// 设备 A 添加两条并首推
	if err := vA.Add("GitHub", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	if err := vA.Add("Steam", testSecret, AlgoHOTP, 3); err != nil {
		t.Fatal(err)
	}
	res, err := DoSync(vA, cfg)
	if err != nil {
		t.Fatalf("首次同步: %v", err)
	}
	if res.RemoteExisted || !res.Pushed {
		t.Fatalf("首次同步结果不符: %+v", res)
	}

	// 设备 B 拉取：应并入 2 条
	res, err = DoSync(vB, cfg)
	if err != nil {
		t.Fatalf("设备 B 拉取: %v", err)
	}
	if !res.RemoteExisted || res.Added != 2 {
		t.Fatalf("设备 B 拉取结果不符: %+v", res)
	}
	if e, err := vB.Get("Steam"); err != nil || e.Counter != 3 || e.Algo != AlgoHOTP {
		t.Fatalf("设备 B 应取回 Steam(HOTP,counter=3): %+v, %v", e, err)
	}

	// 设备 B 修改 GitHub → 推送 → 设备 A 拉到更新
	if err := vB.Update("GitHub", "GitHub", testSecret2, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	bumpEntry(t, vB, "GitHub", time.Minute)
	if res, err = DoSync(vB, cfg); err != nil {
		t.Fatalf("设备 B 推送修改: %v", err)
	}
	if res.Updated != 0 || res.Added != 0 {
		t.Fatalf("B 本地无远端变化, 结果应为空: %+v", res)
	}
	if res, err = DoSync(vA, cfg); err != nil {
		t.Fatalf("设备 A 拉取修改: %v", err)
	}
	if res.Updated != 1 {
		t.Fatalf("设备 A 应更新 1 条: %+v", res)
	}
	if e, _ := vA.Get("GitHub"); e.Secret != testSecret2 {
		t.Fatalf("设备 A 的 GitHub 内容应为远端新版: %+v", e)
	}

	// 设备 A 删除 Steam（墓碑传播到 B）
	if err := vA.Remove("Steam"); err != nil {
		t.Fatal(err)
	}
	bumpTombstone(t, vA, "Steam", time.Minute)
	if _, err = DoSync(vA, cfg); err != nil {
		t.Fatalf("设备 A 推送删除: %v", err)
	}
	if res, err = DoSync(vB, cfg); err != nil {
		t.Fatalf("设备 B 拉取删除: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("设备 B 应因墓碑删除 1 条: %+v", res)
	}
	if _, err := vB.Get("Steam"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Steam 应已从设备 B 删除: %v", err)
	}

	// 收敛检查：两端条目与墓碑完全一致
	namesOf := func(v *Vault) []string {
		var out []string
		for _, e := range v.Entries() {
			out = append(out, e.Name)
		}
		return out
	}
	aNames, bNames := namesOf(vA), namesOf(vB)
	if len(aNames) != 1 || aNames[0] != "GitHub" || len(bNames) != 1 || bNames[0] != "GitHub" {
		t.Fatalf("两端未收敛: A=%v B=%v", aNames, bNames)
	}
	if len(vA.Deleted()) != 1 || len(vB.Deleted()) != 1 {
		t.Fatalf("两端墓碑数应一致且为 1: A=%d B=%d", len(vA.Deleted()), len(vB.Deleted()))
	}

	// 同步密码错误必须被拒绝
	badCfg := *cfg
	badCfg.SyncPassword = "wrong-sync-pass"
	if _, err := DoSync(vA, &badCfg); err == nil || !strings.Contains(err.Error(), "解密失败") {
		t.Fatalf("同步密码错误应报解密失败, got %v", err)
	}
}

// TestDoSyncRemotePathNormalization 远端路径允许带开头斜杠 / 反斜杠，且空目录层级不触发 MKCOL。
func TestDoSyncRemotePathNormalization(t *testing.T) {
	srv := newWebDAVTestServer(t)
	v := newTestVault(t, t.TempDir())
	defer v.Close()
	if err := v.Add("X", testSecret, AlgoTOTP, 0); err != nil {
		t.Fatal(err)
	}
	cfg := &SyncConfig{
		ServerURL:    srv.URL + "/", // 尾斜杠应被归一化
		SyncPassword: "sp",
		RemotePath:   "/sync.enc", // 开头斜杠应被归一化（根目录文件）
	}
	if _, err := DoSync(v, cfg); err != nil {
		t.Fatalf("根目录同步文件应可用: %v", err)
	}
}
