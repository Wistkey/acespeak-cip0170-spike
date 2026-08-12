/**
 * Minimal .env loader.
 *
 * Deliberately not a dependency: this repo is evidence for a grant application,
 * and every package a reviewer has to trust is a package they have to read.
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

let loaded = false;

export function loadEnv(path = resolve(process.cwd(), '.env')): void {
    if (loaded || !existsSync(path)) return;
    loaded = true;

    for (const line of readFileSync(path, 'utf8').split('\n')) {
        const trimmed = line.trim();
        if (trimmed === '' || trimmed.startsWith('#')) continue;

        const eq = trimmed.indexOf('=');
        if (eq === -1) continue;

        const key = trimmed.slice(0, eq).trim();
        let value = trimmed.slice(eq + 1).trim();

        if (
            (value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))
        ) {
            value = value.slice(1, -1);
        }
        if (process.env[key] === undefined) process.env[key] = value;
    }
}

/** Read a required variable, failing with an actionable message rather than undefined. */
export function required(name: string): string {
    loadEnv();
    const value = process.env[name];
    if (value === undefined || value === '') {
        throw new Error(`${name} is not set. Copy .env.example to .env and fill it in.`);
    }
    return value;
}

/** Read an optional variable with a fallback. */
export function optional(name: string, fallback: string): string {
    loadEnv();
    const value = process.env[name];
    return value === undefined || value === '' ? fallback : value;
}
