// Registers the "@/*" alias resolver hook. Loaded via `--import` before the
// test files run.
import { register } from 'node:module';

register('./alias-hook.mjs', import.meta.url);
