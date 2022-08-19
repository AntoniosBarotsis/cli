import { PhylumApi } from 'phylum';

const spdxVersion = "SPDX-2.1";
const spdxId = "SPDXRef-DOCUMENT";
const creator = "Tool: github.com/phylum-dev/cli";
const creatorComment = "SBOM Document for the XYZ project from Phylum, Inc.";

interface Dependency {
    name: string;
    version: string;
}

interface Package {
    name: string;
    version: string;
    license: string;
    type: string;
    dependencies: Dependency[];
}

/**
 *
 */
function getHomepage(pkg: Package) {
    switch(pkg.type) {
        case 'npm':
            return `https://www.npmjs.com/package/${pkg.name}/v/${pkg.version}`;
        case 'pypi':
            return `https://pypi.org/project/${pkg.version}/${pkg.version}/`;
        case 'rubygems':
            return `https://rubygems.org/gems/${pkg.name}/versions/${pkg.version}`;
        case 'maven':
            return ``; // TODO: How do we handle this? Maven central? What about others?
        case 'nuget':
            return `https://www.nuget.org/packages/${pkg.name}/${pkg.version}`;
        default:
            return 'NOASSERTION';
    }
}

/**
 *  Generates the document header for the produced SBOM.
 */
async function generateDocumentHeader(string, docNamespace: string, licenseListVersion: string) {
    // TODO: need to capture
    //  * DocumentNamespace (Not sure???)
    //  * LicenseListVersion (Not sure???)
    const projectDetails = await PhylumApi.getProjectDetails();
    const docName = projectDetails["name"];

    const dataLicense = "FOOBAR";
    const today = new Date().toISOString();
    return `##Document Header\n` + 
           `SPDXVersion: ${spdxVersion}\n` +
           `DataLicense: ${dataLicense}\n` +
           `SPDXID: ${spdxId}` +
           `DocumentName: ${docName}\n` +
           `DocumentNamespace: ${docNamespace}\n` + 
           `Creator: ${creator}\n` +
           `Created: ${today}\n` +
           `CreatorComment: <text>${creatorComment}</text>\n\n`;
}

/**
 *  Creates a package block for the provided package JSON.
 */
function createPackageBlock(pkg: Package) {
    return `##### Package: ${pkg.name}\n\n` +
           `PackageName: ${pkg.name}\n` +
           `SPDXID: SPDXRef-${pkg.name}-${pkg.version}\n` +
           `PackageVersion: ${pkg.version}\n` +
           `PackageDownloadLocation: NOASSERTION\n` + // TODO: Get this!
           `FilesAnalyzed: true\n` +
           `PackageHomePage: ${getHomepage(pkg)}\n` +
           `PackageLicenseConcluded: NOASSERTION\n` + // TODO: Get this!
           `PackageLicenseDeclared: ${pkg.license}\n` +
           `PackageCopyrightText: NOASSERTION\n` +
           `ExternalRef: PACKAGE-MANAGER ${pkg.type} ${pkg.name}@${pkg.version}\n\n`
}

/**
 *  Creates a relationship entry for the provided package JSON.
 */
function createRelationship(pkg: string, ver: string, dep: Dependency) {
    return `Relationship: SPDXRef-${dep.name}-${dep.version} PREREQUISITE_FOR SPDXRef-${pkg}-${ver}\n`;
}

/**
 *  Given a Phylum job JSON, generates the SBOM document and drops
 *  it to disk.
 */
async function toSBOM(data: string) {
    let jobData = JSON.parse(data);
    //let sbom = await generateDocumentHeader("bar", "test");
    let sbom = "";
    let refs = "";

    // Construct the packages section of our SBOM
    jobData["packages"].forEach((p) => {
        let pkg: Package = p;
        sbom += createPackageBlock(pkg);

        let pkgName: keyof typeof obj;

        // Create the package relationships of our SBOM
        for (pkgName in pkg.dependencies) {
            let version = pkg.dependencies[pkgName];
            let dep = { name: pkgName, version: version };
            refs += createRelationship(pkg.name, pkg.version, dep);
        }
    });

    return sbom + `##### Relationships\n\n${refs}`; 
}

const text = await Deno.readTextFile("./phylum.json");


// TODO:
// * Need to get `other licenses`
const sbom = await toSBOM(text);
console.log(sbom);
