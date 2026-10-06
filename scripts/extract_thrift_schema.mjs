import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [sourceArg, outputArg] = process.argv.slice(2);
if (!sourceArg || !outputArg) {
	throw new Error("usage: node scripts/extract_thrift_schema.mjs <linejs-thrift.ts> <schema.json>");
}

const sourceURL = pathToFileURL(resolve(sourceArg));
const source = await import(sourceURL.href);
if (!source.Thrift || typeof source.Thrift !== "object") {
	throw new Error(`source ${sourceURL.pathname} does not export Thrift metadata`);
}

const outputPath = resolve(outputArg);
await writeFile(outputPath, `${JSON.stringify(source.Thrift)}\n`);
process.stdout.write(`wrote LINE Thrift schema to ${outputPath}\n`);
