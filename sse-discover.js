var cpuid = require('cpuid');
var cpuidInfo = cpuid();

if (cpuidInfo.features.sse && cpuidInfo.features.sse2) {
        console.log("true");
} else {
        console.log("false");
}
