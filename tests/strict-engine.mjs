// Regression profile for the still-supported all-address detector. New default
// country behavior is covered separately, without changing these expectations.
import {compile as compileCore,defaults as current} from '../dist/core.js';
export const defaults=structuredClone(current);
defaults.rules[0].detector.mode='any';
delete defaults.rules[0].detector.country;
delete defaults.rules[0].detector.onUnknown;
export const compile=(config=defaults)=>compileCore(config);
