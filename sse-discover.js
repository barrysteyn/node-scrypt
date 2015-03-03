/*
 *Script for determining if SSE support is available
 */

var os = require("os");

switch(os.arch()) {
	case 'ia32':
	case 'x64':
		console.log("true");
		break;
	case 'arm':
	default:
		console.log("false");
};
