import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

// Test for ALL methods on /{language}
test('ALL /{language}', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'excessive_data_exposure', 'http_method_fuzzing', 'xss', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET, // Using GET as a representative method for the test
      url: `${baseUrl}/{language}`
    });
});
