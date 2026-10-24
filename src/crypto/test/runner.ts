export interface TestResult {
    name:    string;
    passed:  boolean;
    error?:  string;
    duration: number;
}

export interface SuiteResult {
    name:    string;
    results: TestResult[];
    passed:  number;
    failed:  number;
    duration: number;
}

export class TestRunner {
    private results: TestResult[] = [];
    private suiteName: string;

    constructor(suiteName: string) {
        this.suiteName = suiteName;
    }

    test(name: string, fn: () => void): void {
        const start = performance.now();
        try {
            fn();
            this.results.push({ name, passed: true, duration: performance.now() - start });
        } catch (err: any) {
            this.results.push({ name, passed: false, error: err?.message ?? String(err), duration: performance.now() - start });
        }
    }

    assert(condition: boolean, message: string): void {
        if (!condition) throw new Error(message);
    }

    summary(): SuiteResult {
        const passed  = this.results.filter(r => r.passed).length;
        const failed  = this.results.filter(r => !r.passed).length;
        const duration = this.results.reduce((acc, r) => acc + r.duration, 0);
        return { name: this.suiteName, results: this.results, passed, failed, duration };
    }
}

export function printResults(suites: SuiteResult[]): void {
    const totalPassed  = suites.reduce((a, s) => a + s.passed, 0);
    const totalFailed  = suites.reduce((a, s) => a + s.failed, 0);
    const totalDuration = suites.reduce((a, s) => a + s.duration, 0);

    for (const suite of suites) {
        console.log(`\n  ${suite.name}`);
        for (const r of suite.results) {
            const icon = r.passed ? '✅' : '❌';
            const time = `(${r.duration.toFixed(2)}ms)`;
            console.log(`    ${icon} ${r.name} ${time}`);
            if (!r.passed && r.error) console.log(`       → ${r.error}`);
        }
    }

    console.log(`\n${'─'.repeat(50)}`);
    console.log(`  ${totalPassed} passed, ${totalFailed} failed  (${totalDuration.toFixed(2)}ms)`);
    console.log(`${'─'.repeat(50)}\n`);

    if (totalFailed > 0) process.exit(1);
}