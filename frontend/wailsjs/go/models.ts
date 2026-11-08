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

}

