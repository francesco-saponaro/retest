#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { run } from "./run.js";

process.exitCode = await run(process.argv.slice(2), process.env, {
  fetch: (input, init) => fetch(input, init),
  readFile: (path) => readFile(path, "utf8"),
  writeFile: (path, text) => writeFile(path, text, "utf8"),
  out: (line) => process.stdout.write(`${line}\n`),
  err: (line) => process.stderr.write(`${line}\n`),
});
