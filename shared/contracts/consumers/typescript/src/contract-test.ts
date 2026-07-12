import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import Ajv2020, {type ErrorObject} from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

type Fixture = {path: string; schema: string; valid: boolean; error: string | null};
type FixtureManifest = {fixtures: Fixture[]};

const root = process.env.WTO_CONTRACT_ROOT ?? path.resolve("../..");
const schemasDirectory = path.join(root, "schemas");
const examplesDirectory = path.join(root, "examples");
const ajv = new Ajv2020({allErrors: true, strict: true, allowUnionTypes: true, validateFormats: true});
addFormats(ajv);

for (const name of fs.readdirSync(schemasDirectory).filter((item) => item.endsWith(".schema.json")).sort()) {
  const schema = JSON.parse(fs.readFileSync(path.join(schemasDirectory, name), "utf8"));
  ajv.addSchema(schema);
}

const manifest = JSON.parse(
  fs.readFileSync(path.join(examplesDirectory, "manifest.json"), "utf8"),
) as FixtureManifest;
const failures: string[] = [];
for (const fixture of manifest.fixtures) {
  const schema = JSON.parse(fs.readFileSync(path.join(schemasDirectory, fixture.schema), "utf8"));
  const payload = JSON.parse(fs.readFileSync(path.join(examplesDirectory, fixture.path), "utf8"));
  const validate = ajv.getSchema(schema.$id) ?? ajv.compile(schema);
  const valid = validate(payload) as boolean;
  if (valid !== fixture.valid) failures.push(`${fixture.path}: expected valid=${fixture.valid}`);
  if (!valid && fixture.error !== null) {
    const keywords = new Set((validate.errors ?? []).map((item: ErrorObject) => item.keyword));
    if (!keywords.has(fixture.error)) failures.push(`${fixture.path}: missing ${fixture.error}; got ${[...keywords]}`);
  }
}
if (failures.length > 0) throw new Error(failures.join("\n"));
console.log(`TypeScript/Ajv validated ${manifest.fixtures.length} normative fixtures.`);
