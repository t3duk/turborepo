import { setupTestFixtures } from "@turbo/test-utils";
import { SchemaV2, type Schema } from "@turbo/types";
import { describe, it, expect } from "@jest/globals";
import {
  transformer,
  migrateConfig,
} from "../src/transforms/set-default-outputs";

describe("set-default-outputs", () => {
  const { useFixture } = setupTestFixtures({
    directory: __dirname,
    test: "set-default-outputs",
  });

  it("skips when no pipeline key", () => {
    const config: SchemaV2 = {
      $schema: "./docs/public/schema.json",
      globalDependencies: ["$GLOBAL_ENV_KEY"],
      tasks: {
        test: {
          outputs: ["coverage/**/*"],
          dependsOn: ["^build"],
        },
        lint: {
          outputs: [],
        },
        dev: {
          cache: false,
        },
        build: {
          outputs: ["dist/**/*", ".next/**/*", "!.next/cache/**"],
          dependsOn: ["^build", "$TASK_ENV_KEY", "$ANOTHER_ENV_KEY"],
        },
      },
    };

    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-explicit-any -- Testing a situation outside of types that users can get themselves into at runtime
    const doneConfig = migrateConfig(config as any);

    expect(doneConfig).toEqual(config);
  });

  it("migrates turbo.json outputs - basic", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "old-outputs",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(JSON.parse(read("turbo.json") || "{}")).toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      pipeline: {
        "build-one": {
          outputs: ["foo"],
        },
        "build-two": {},
        "build-three": {
          outputs: ["dist/**", "build/**"],
        },
      },
    });

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "modified",
          "additions": 2,
          "deletions": 1,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - workspace configs", () => {
    // load the fixture for the test
    const { root, readJson } = useFixture({
      fixture: "workspace-configs",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(readJson("turbo.json") || "{}").toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      pipeline: {
        "build-one": {
          outputs: ["foo"],
        },
        "build-two": {},
        "build-three": {
          outputs: ["dist/**", "build/**"],
        },
      },
    });

    expect(readJson("apps/docs/turbo.json") || "{}").toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      extends: ["//"],
      pipeline: {
        build: {
          outputs: ["dist/**", "build/**"],
        },
      },
    });

    expect(readJson("apps/web/turbo.json") || "{}").toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      extends: ["//"],
      pipeline: {
        build: {},
      },
    });

    expect(readJson("packages/ui/turbo.json") || "{}").toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      extends: ["//"],
      pipeline: {
        "build-three": {
          outputs: ["dist/**", "build/**"],
        },
      },
    });

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "apps/docs/turbo.json": {
          "action": "modified",
          "additions": 1,
          "deletions": 1,
        },
        "apps/web/turbo.json": {
          "action": "modified",
          "additions": 1,
          "deletions": 0,
        },
        "packages/ui/turbo.json": {
          "action": "modified",
          "additions": 1,
          "deletions": 1,
        },
        "turbo.json": {
          "action": "modified",
          "additions": 2,
          "deletions": 1,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - dry", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "old-outputs",
    });

    const turboJson = JSON.parse(read("turbo.json") || "{}") as Schema;

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: true, print: false },
    });

    // make sure it didn't change
    expect(JSON.parse(read("turbo.json") || "{}")).toEqual(turboJson);

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "skipped",
          "additions": 2,
          "deletions": 1,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - print", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "old-outputs",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: true },
    });

    expect(JSON.parse(read("turbo.json") || "{}")).toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      pipeline: {
        "build-one": {
          outputs: ["foo"],
        },
        "build-two": {},
        "build-three": {
          outputs: ["dist/**", "build/**"],
        },
      },
    });

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "modified",
          "additions": 2,
          "deletions": 1,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - dry & print", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "old-outputs",
    });

    const turboJson = JSON.parse(read("turbo.json") || "{}") as Schema;

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: true, print: false },
    });

    // make sure it didn't change
    expect(JSON.parse(read("turbo.json") || "{}")).toEqual(turboJson);

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "skipped",
          "additions": 2,
          "deletions": 1,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - invalid", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "invalid-outputs",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(JSON.parse(read("turbo.json") || "{}")).toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      pipeline: {
        "build-one": {
          outputs: ["foo"],
        },
        "build-two": {},
        "build-three": {
          outputs: ["dist/**", "build/**"],
        },
        "garbage-in-numeric-0": {
          outputs: ["dist/**", "build/**"],
        },
        "garbage-in-numeric": {
          outputs: 42,
        },
        "garbage-in-string": {
          outputs: "string",
        },
        "garbage-in-empty-string": {
          outputs: ["dist/**", "build/**"],
        },
        "garbage-in-null": {
          outputs: ["dist/**", "build/**"],
        },
        "garbage-in-false": {
          outputs: ["dist/**", "build/**"],
        },
        "garbage-in-true": {
          outputs: true,
        },
        "garbage-in-object": {
          outputs: {},
        },
      },
    });

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "modified",
          "additions": 6,
          "deletions": 5,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - config with no pipeline", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "no-pipeline",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(JSON.parse(read("turbo.json") || "{}")).toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      globalDependencies: ["$NEXT_PUBLIC_API_KEY", "$STRIPE_API_KEY", ".env"],
      pipeline: {},
    });

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "unchanged",
          "additions": 0,
          "deletions": 0,
        },
      }
    `);
  });

  it("migrates turbo.json outputs - config with no outputs", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "no-outputs",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(JSON.parse(read("turbo.json") || "{}")).toStrictEqual({
      $schema: "https://turbo.build/schema.json",
      pipeline: {
        "build-one": {
          dependsOn: ["build-two"],
          outputs: ["dist/**", "build/**"],
        },
        "build-two": {
          cache: false,
        },
        "build-three": {
          persistent: true,
          outputs: ["dist/**", "build/**"],
        },
      },
    });

    expect(result.fatalError).toBeUndefined();
    expect(result.changes).toMatchInlineSnapshot(`
      {
        "turbo.json": {
          "action": "modified",
          "additions": 2,
          "deletions": 0,
        },
      }
    `);
  });

  it("errors if no turbo.json can be found", () => {
    // load the fixture for the test
    const { root, read } = useFixture({
      fixture: "no-turbo-json",
    });

    expect(read("turbo.json")).toBeUndefined();

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(read("turbo.json")).toBeUndefined();
    expect(result.fatalError).toBeDefined();
    expect(result.fatalError?.message).toMatch(
      /No turbo\.json found at .*?\. Is the path correct\?/
    );
  });

  it("errors if package.json config exists and has not been migrated", () => {
    // load the fixture for the test
    const { root } = useFixture({
      fixture: "old-config",
    });

    // run the transformer
    const result = transformer({
      root,
      options: { force: false, dryRun: false, print: false },
    });

    expect(result.fatalError).toBeDefined();
    expect(result.fatalError?.message).toMatch(
      'turbo" key detected in package.json. Run `npx @turbo/codemod transform create-turbo-config` first'
    );
  });
});
