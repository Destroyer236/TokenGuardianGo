export namespace core {
	
	export class ImportResult {
	    imported: number;
	    duplicates: number;
	    invalid: number;
	    tombstoneOnly: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ImportResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.imported = source["imported"];
	        this.duplicates = source["duplicates"];
	        this.invalid = source["invalid"];
	        this.tombstoneOnly = source["tombstoneOnly"];
	    }
	}
	export class RemoteFileInfo {
	    exists: boolean;
	    size: number;
	    // Go type: time
	    modTime: any;
	
	    static createFrom(source: any = {}) {
	        return new RemoteFileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.exists = source["exists"];
	        this.size = source["size"];
	        this.modTime = this.convertValues(source["modTime"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SyncResult {
	    added: number;
	    updated: number;
	    deleted: number;
	    remoteExisted: boolean;
	    pushed: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SyncResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.added = source["added"];
	        this.updated = source["updated"];
	        this.deleted = source["deleted"];
	        this.remoteExisted = source["remoteExisted"];
	        this.pushed = source["pushed"];
	    }
	}

}

export namespace main {
	
	export class CodeInfo {
	    name: string;
	    algo: string;
	    code: string;
	    secondsRemaining: number;
	    counter: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new CodeInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.algo = source["algo"];
	        this.code = source["code"];
	        this.secondsRemaining = source["secondsRemaining"];
	        this.counter = source["counter"];
	        this.error = source["error"];
	    }
	}
	export class EntryFull {
	    name: string;
	    algo: string;
	    counter: number;
	    updatedAt: string;
	    secret: string;
	
	    static createFrom(source: any = {}) {
	        return new EntryFull(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.algo = source["algo"];
	        this.counter = source["counter"];
	        this.updatedAt = source["updatedAt"];
	        this.secret = source["secret"];
	    }
	}
	export class EntryInfo {
	    name: string;
	    algo: string;
	    counter: number;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new EntryInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.algo = source["algo"];
	        this.counter = source["counter"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class SyncSettingsInfo {
	    configured: boolean;
	    serverUrl: string;
	    username: string;
	    remotePath: string;
	    noSyncDeletions: boolean;
	    lastSyncAt: string;
	    lastSyncText: string;
	    lastSyncError?: string;
	
	    static createFrom(source: any = {}) {
	        return new SyncSettingsInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.configured = source["configured"];
	        this.serverUrl = source["serverUrl"];
	        this.username = source["username"];
	        this.remotePath = source["remotePath"];
	        this.noSyncDeletions = source["noSyncDeletions"];
	        this.lastSyncAt = source["lastSyncAt"];
	        this.lastSyncText = source["lastSyncText"];
	        this.lastSyncError = source["lastSyncError"];
	    }
	}

}

