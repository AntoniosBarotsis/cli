
export type PackageEcosystem = "npm" | "pypi" | "rubygems" | "maven" | "nuget" | "golang" | "cargo";
export type SeverityType = "low" | "medium" | "high" | "critical" | "nil";
export enum Domain {
    Malware = "malicious_code",
    Author = "author",
    Engineering = "engineering",
    License = "license",
    Vulnerability = "vulnerability",
    All = "total",
}

export type RiskVector = {
    author: number,
    vulnerabilities: number,
    engineering: number,
    malicious_code: number,
    license: number,
    total: number
};

export type IssueDef = {
    tag: string,
    title: string,
    description: string,
    severity: SeverityType,
    domain: Domain
}

export type PackageDef = {
    name: string,
    version: string,
    status: string,
    license: string,
    package_score: number,
    num_dependencies: number,
    num_vulnerabilities: number,
    type: PackageEcosystem,
    riskVectors: RiskVector,
    dependencies: Object,
    issues: IssueDef[],
}

function buildIssueDefFromObject(iData: Object): IssueDef {
    return {
        tag: iData['tag'],
        title: iData['title'],
        description: iData['description'],
        severity: iData['severity'],
        domain: iData['domain'],
    };
}

function buildRiskVectorFromObject(rvData: Object): RiskVector {
    return {
        author: rvData['author'],
        vulnerabilities: rvData['vulnerabilities'],
        total: rvData['total'],
        engineering: rvData['engineering'],
        malicious_code: rvData['malicious_code'],
        license: rvData['license'],
    };
}

export function packageDefinitionFromObject(packageData: Array<Object>): PackageDef[] {
    let pList: PackageDef[] = [];

    for(const p of packageData) {
        let tmp = {
            name: p['name'],
            version: p['version'],
            status: p['status'],
            license: p['license'],
            package_score: p['package_score'],
            num_dependencies: p['num_dependencies'],
            num_vulnerabilities: p['num_vulnerabilities'],
            type: p['type'],
            riskVectors: buildRiskVectorFromObject(p['riskVectors']),
            dependencies: p['dependencies'],
            issues: [],
        };

        for(const i of p['issues']) {
            tmp.issues.push(buildIssueDefFromObject(i));
        }

        pList.push(tmp);
    }

    return pList;
}


export enum Action {
    Abort = "abort",
    Warn = "warn",
    Log = "log",
    Ignore = "ignore",
}

enum KeyType {
    If = "if",
    Any = "any",
    All = "all",
    Risks = "risks",
    Issue = "issue",
    Health = "health",
    License = "license",
    Author = "author",
}

enum FilterDomain {
    Malware = "malware",
    Engineering = "engineering",
    License = "license",
    Author = "author",
    Vulnerability = "vulnerability",
}

type FilterType = "is" | "not" | "less" | "greater" | "lte" | "gte";
type Nullable = string | undefined | null | number;
type NullableArray = string[] | undefined | null | number[];

type FilterResult = {
    pass: boolean,
    messages: string[],
};

type DomainFilter = {
    domain: FilterDomain,
    severity: SeverityType,
    tag?: string,
    threshold?: number,
};

export type Filter = (ps: PackageDef[]) => FilterResult;

export type Rule = {
    label: string,
    description: string,
    action: Action,
    filters: Filter[],
}

function issueBuilder(data: Object): Filter {
    let tag: Nullable = data["tag"];
    let sev: Nullable = data["severity"];


    return (pkgs: PackageDef[]) => {
        let tmp: FilterResult = {pass: true, messages: []};

        for(let pkg: PackageDef of pkgs) {
            for(let issue: IssueDef of pkg.issues) {
                if(tag && issue.tag === tag) {
                    tmp.pass = false;
                    tmp.messages = tmp.messages.concat(`package "${pkg.name}:${pkg.version}" has issue "${issue.tag}"`);
                }

                if (sev && issue.severity === sev) {
                    tmp.pass = false;
                    tmp.messages = tmp.messages.concat(`package "${pkg.name}:${pkg.version}" has an issue with severity ${sev}`);
                }
            }
        }

        return tmp;
    };
}

function filterToDomain(df: string): Domain {
    switch(df) {
        case FilterDomain.Malware:
            return Domain.Malware;
        case FilterDomain.Engineering:
            return Domain.Engineering;
        case FilterDomain.Author:
            return Domain.Author;
        case FilterDomain.Vulnerability:
            return Domain.Vulnerability;
        case FilterDomain.License:
            return Domain.License;
        default:
            throw new TypeError(`invalid domain type '${df}' provided`);
    }
}

function generateErrorString(packageName: string, packageVersion: string, message: string): string {
    return `package "${packageName}:${packageVersion}" has ${message}`;
}

function riskBuilder(data: Object): Filter {
    const keys = Object.keys(data);
    let dom = {};

    for(let k of keys) {
        const ob = data[k];
        const severity: Nullable = ob["severity"];
        const tag: Nullable = ob["tag"];
        const threshold: Nullable = ob["score_threshold"];

        let dm: DomainFilter = {
            domain: k,
            severity: severity ? severity : "nil",
            tag: tag,
            threshold: threshold,
        };

        dom[filterToDomain(k)] = dm;
    }

    return (packages: PackageDef[]) => {
        let tmp: FilterResult = {
            pass: true,
            messages: [],
        };

        for(let p: PackageDef of packages) {
            const rv = p.riskVectors;
            for(let filterEntry of dom.keys()) {
                const domFilter: DomainFilter = dom[filterEntry];

                if(domFilter.threshold) {
                    let comparator: number = 0;
                    switch(domFilter.domain) {
                        case FilterDomain.License:
                            comparator = rv.license;
                            break;
                        case FilterDomain.Author:
                            comparator = rv.author;
                            break;
                        case FilterDomain.Malware:
                            comparator = rv.malicious_code;
                            break;
                        case FilterDomain.Engineering:
                            comparator = rv.engineering;
                            break;
                        case FilterDomain.Vulnerability:
                            comparator = rv.vulnerabilities;
                            break;
                        default:
                            throw new TypeError(`unexpected domain ${domainInner} provided`);
                    }

                    if(domFilter.threshold > comparator) {
                        tmp.pass = false;
                        tmp.messages = tmp.messages.push(`${domFilter.domain} risk domain for ${p.name}:${p.version} score at ${comparator} - must be at least ${domFilter.threshold}`);
                    }
                }
            }

            for(let issue: IssueDef of p.issues) {
                const domainFilter = dom[issue.domain];
                if(!domainFilter)
                    continue;

                if(domainFilter.severity === issue.severity) {
                    tmp.pass = false;
                    tmp.messages =
                        tmp.messages.concat(generateErrorString(p.name,
                            p.version,
                            `"${issue.tag}" with severity "${issue.severity}"`));
                }


                if(domainFilter.tag && domainFilter.tag === issue.tag) {
                    tmp.pass = false;
                    tmp.messages = tmp.messages.concat(generateErrorString(p.name, p.version, `issue "${issue.tag}"`));
                }
            }
        }

        return tmp;
    };
}

function authorBuilder(data: Object): Filter {
    // TODO: Need to finish this. Not much author data exposed yet.
    return (packages: PackageDef[]): FilterResult => ({pass:true, messages:[]});
}

function healthBuilder(data: Object): Filter {
    // TODO: Need to finish this. Currently, this would require _per-package_ API calls, which is probably
    // not great; would be good to consider
    return (packages: PackageDef[]): FilterResult => {
        return {pass: true, messages: []};
    }
}

function licenseBuilder(data: Object): Filter {
    const isClause: NullableArray = data["is"];
    const notClause: NullableArray = data["not"];

    const efficientIs = isClause ? new Set(isClause) : new Set();
    const efficientNot = notClause ? new Set(notClause) : new Set();

    return (packages: PackageDef[]): FilterResult => {
        let res: FilterResult = {pass: true, messages: []};

        for(let p: PackageDef of packages) {
            if(efficientIs.has(p.license)) {
                res.pass = false;
                res.messages = res.messages.concat(generateErrorString(p.name,
                    p.version,
                    `disallowed license type "${p.license}"`));
            }

            if(efficientNot.size && !efficientNot.has(p.license)) {
                res.pass = false;
                res.messages = res.messages.concat(generateErrorString(p.name, p.version,
                    `disallowed license type "${p.license}"`));
            }
        }

        return res;
    }
}

function buildFilters(key: string, data: Object | Array): Filter[] {
    let filters: Filter[] = [];

    const kV = (entry: Object): Array => {
        const k = Object.keys(entry);
        if(k.length > 1)
            throw new Error("Rule definitions in a list should have at most one type!");

        const realKey: string = k[0];

        return [realKey, entry[realKey]];
    }

    switch(key) {
        case KeyType.If:
            const keyList = Object.keys(data);
            for(let ik of keyList) {
                filters = filters.concat(buildFilters(ik, data[ik]));
            }
            break;
        case KeyType.Any:
            // We will error out as soon as *any* of these rules are violated.
            let tmp: Filter[] = [];
            for(let k of data) {
                let [innerkey, v] = kV(k);

                tmp = tmp.concat(buildFilters(innerkey, v))
            }
            filters.push((d: PackageDef[]): FilterResult => {
                for(const f of tmp) {
                    const inner = f(d);
                    if(!inner.pass)
                        return inner;
                }

                return {pass: true, messages: []};
            })
            break;
        case KeyType.All:
            // Here, we will need to check all conditions first, as it will only fail if all are violated.
            let filterList: Filter[] = [];
            for (let k of data) {
                let [innerkey, v] = kV(k);
                filterList = filterList.concat(buildFilters(innerkey, v));
            }

            filters.push((d: PackageDef[]): FilterResult => {
                let count = 0;
                let messages: string[] = [];
                for (const f of filterList) {
                    const inner = f(d);
                    if(!inner.pass) {
                        count++;
                        messages = messages.concat(inner.messages);
                    }
                }

                if(count === filterList.length) {
                    return {
                        pass: false,
                        messages: messages,
                    };
                }

                return {
                    pass: true,
                    messages: messages,
                };
            });
            break;
        case KeyType.Issue:
            filters.push(issueBuilder(data));
            break;
        case KeyType.Risks:
            filters.push(riskBuilder(data));
            break;
        case KeyType.Health:
            filters.push(healthBuilder(data));
            break;
        case KeyType.License:
            filters.push(licenseBuilder(data));
            break;
        case KeyType.Author:
            filters.push(authorBuilder(data));
            break;
        default:
            throw new Error(`Error: unrecognized action "${key}" provided`);
    }

    return filters;
}

function buildRule(key: string, value: any): Rule {

    const skipValues = new Set(["description", "action"]);

    const descr: Nullable = value["description"];
    const action: Nullable = value["action"];

    let filterCallbacks: Filter[] = [];

    if (!descr || !action)
        throw new Error(`Rule "${key}" missing either description or action!`);


    for(let k of Object.keys(value)) {
        if (skipValues.has(k))
            continue;

        filterCallbacks = filterCallbacks.concat(buildFilters(k, value[k]));
    }


    let r: Rule = {
        label: key,
        description: descr,
        action: action,
        filters: filterCallbacks,
    }

    return r;
}

function handleRules(data: Object): Rule[] {
    const ruleEntries = Object.keys(data);
    let ruleValues: Rule[] = [];

    for (let key of ruleEntries) {
        ruleValues.push(buildRule(key, data[key]));
    }

    return ruleValues;
}

export function buildRules(data: Object): Rule[] {
    return handleRules(data);
}

export type RuleAction = {
    pass: boolean,
    label: string,
    description: string,
    action: Action,
    message: string
};

export type RuleResult = {
    pass: boolean,
    actions: RuleAction[],
}

function coalesceFilterResults(label: string, description: string, action: Action, res: FilterResult[]): RuleAction {
    let tmp = {
        pass: true,
        label: label,
        description: description,
        action: action,
        message: "",
    };

    let totalMessage: string[] = [];

    for (const r of res) {
        if(!r.pass)
            tmp.pass = false;

        totalMessage = totalMessage.concat(r.messages);
    }

    tmp.message = totalMessage.join("\n");

    return tmp;
}

export function applyRules(rules: Rule[], packages: PackageDef[]): RuleResult {
    let res: RuleResult = {pass: true, actions: []};

    for(const rule of rules) {
        let tmpRes: FilterResult[] = [];

        for (const filt of rule.filters) {
            tmpRes = tmpRes.concat(filt(packages));
        }

        const action = coalesceFilterResults(rule.label, rule.description, rule.action, tmpRes);

        if(!action.pass)
            res.pass = false;

        res.actions.push(action);
    }

    return res;
}