/*
 *Script for determining if SSE support is available
 */

try {
    var cpuid = require('cpuid');

    try {
            var cpuidInfo = cpuid();
            if (cpuidInfo.features.sse && cpuidInfo.features.sse2) {
                    console.log("true");
                    process.exit(0);
            }
    } catch (error) {}
} catch(error) {}
console.log("false");
