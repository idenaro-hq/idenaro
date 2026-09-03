export namespace main {
	
	export class CountsDTO {
	    critical: number;
	    high: number;
	    medium: number;
	    low: number;
	    info: number;
	    total: number;
	    chain: number;
	
	    static createFrom(source: any = {}) {
	        return new CountsDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.critical = source["critical"];
	        this.high = source["high"];
	        this.medium = source["medium"];
	        this.low = source["low"];
	        this.info = source["info"];
	        this.total = source["total"];
	        this.chain = source["chain"];
	    }
	}
	export class FindingDTO {
	    id: string;
	    module: string;
	    title: string;
	    description: string;
	    severity: string;
	    confidence: string;
	    riskScore: number;
	    evidence: string[];
	    recommendation: string;
	    nis2Articles: string[];
	    tags: string[];
	    isChain: boolean;
	
	    static createFrom(source: any = {}) {
	        return new FindingDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.module = source["module"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.severity = source["severity"];
	        this.confidence = source["confidence"];
	        this.riskScore = source["riskScore"];
	        this.evidence = source["evidence"];
	        this.recommendation = source["recommendation"];
	        this.nis2Articles = source["nis2Articles"];
	        this.tags = source["tags"];
	        this.isChain = source["isChain"];
	    }
	}
	export class LicenseStatusDTO {
	    licensed: boolean;
	    email?: string;
	    exp?: string;
	
	    static createFrom(source: any = {}) {
	        return new LicenseStatusDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.licensed = source["licensed"];
	        this.email = source["email"];
	        this.exp = source["exp"];
	    }
	}
	export class ScanResultDTO {
	    host: string;
	    overallScore: number;
	    duration: string;
	    error?: string;
	    findings: FindingDTO[];
	    counts: CountsDTO;
	
	    static createFrom(source: any = {}) {
	        return new ScanResultDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.overallScore = source["overallScore"];
	        this.duration = source["duration"];
	        this.error = source["error"];
	        this.findings = this.convertValues(source["findings"], FindingDTO);
	        this.counts = this.convertValues(source["counts"], CountsDTO);
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

}

