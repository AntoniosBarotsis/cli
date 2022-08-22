import {Action, applyRules, buildRules, packageDefinitionFromObject, Rule, RuleResult} from "./policy";
import {PhylumApi} from "phylum";
import {green, red, yellow} from 'https://deno.land/std@0.150.0/fmt/colors.ts';
import {parse} from "https://deno.land/std@0.152.0/encoding/yaml.ts";


const DEFAULT_POLICY_PATH = "./.phylum_rules";
const SEP = Deno.build.os === "windows" ? "\\" : "/";
const ECOSYSTEMS_SUPPORTED = new Set(["npm", "pip", "gem", "maven", "nuget", "poetry"]);

async function pathExists(path: string): Promise<boolean> {
    try {
        await Deno.stat(path);
        return true;
    } catch (e) {
        if (e instanceof Deno.errors.NotFound)
            return false;
        else
            throw e;
    }
}

async function loadRules(): Promise<Rule[]> {
    const res = await pathExists(DEFAULT_POLICY_PATH);
    if(!res) {
        throw new Error("no rules found!");
    }

    let rules: Rule[] = [];

    for await (const dentry of Deno.readDir(DEFAULT_POLICY_PATH)) {
        if (!dentry.isFile)
            continue;
        const data = await Deno.readFile(`${DEFAULT_POLICY_PATH}${SEP}${dentry.name}`);

        const parsed = parse(data);

        rules = rules.concat(buildRules(parsed));
    }

    return rules;
}

async function runAnalysis(eco: string, lockfile: string): Promise<Object[]> {
    const lockData = await PhylumApi.parseLockfile(lockfile, eco);
    const jobId = await PhylumApi.analyze(eco, lockData.packages);
    const status = await PhylumApi.getJobStatus(jobId);

    // print messages

    return status.packages;
}

async function handleProject(eco: string, lockfile: string): Promise<RuleResult> {
    const rules = await loadRules();

    const rawPackages = await runAnalysis(eco, lockfile);
    const packages = packageDefinitionFromObject(rawPackages);

    const res = applyRules(rules, packages);

    return res;
}

async function checkPolicy(eco: string, lockfile: string) {
    try {
        const res = await handleProject(eco, lockfile);
        let message = "";
        let shouldFail: boolean = false;

        if(res.pass) {
            console.log(`[${green("phylum")}] All Packages Pass Policy.`)
        } else {
            console.log("---------");
            for (const entry of res.actions) {
                switch(entry.action) {
                    case Action.Abort:
                        shouldFail = true;
                        console.log(`[${red("phylum")}] ${red("FAIL")} > ${entry.label}: ${entry.description}`);
                        console.log(`${red(entry.message)}`);
                        console.log("---------");
                        break;
                    case Action.Log:
                        console.log(`[phylum] LOG > ${entry.label}: ${entry.description}`);
                        console.log(`${entry.message}`);
                        console.log("---------");
                        break;
                    case Action.Warn:
                        console.log(`[${yellow("phylum")}] ${yellow("WARN")} > ${entry.label}: ${entry.description}`);
                        console.log(`${yellow(entry.message)}`);
                        console.log("---------");
                        break;
                    case Action.Ignore:
                        // TODO: At some point we should probably test ignore cases across the full suite of actions
                    default:
                        continue;
                }
            }
        }

    } catch(e) {

    }
}

if(Deno.args.length < 2) {
    console.log(`[${red("phylum")}] Error: Expect 'phylum policy ecosystem lockfile'`);
    Deno.exit(-1);
}

const ecosystem = Deno.args[0];
const lockfile = Deno.args[1];

if(!ECOSYSTEMS_SUPPORTED.has(ecosystem)) {
    console.log(`[${red("phylum")}] Error: Provided ecosystem '${ecosystem}' not currently supported.`);
    Deno.exit(-1);
}

const res = await pathExists(lockfile);
if(!res) {
    console.log(`[${red("phylum")}] Error: Provided lockfile path '${lockfile}' not found.`);
    Deno.exit(-1);
}

await checkPolicy(ecosystem, lockfile);