/*
scrypt_common.cc

Copyright (C) 2013 Barry Steyn (http://doctrina.org/Scrypt-Authentication-For-Node.html)

This source code is provided 'as-is', without any express or implied
warranty. In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this source code must not be misrepresented; you must not
claim that you wrote the original source code. If you use this source code
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.

2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original source code.

3. This notice may not be removed or altered from any source distribution.

Barry Steyn barry.steyn@gmail.com

*/

//Universal constants
const size_t MAXMEM = 0;
const double MAXMEMFRAC = 0.5;

//Forward declarations
std::string ScryptErrorDescr(const int error);

//Structures

/*
 * Holds N,r and p parameters
 */
struct ScryptParams {
	int N;
	uint32_t r;
	uint32_t p;
};

/*
 * Holds maxtime, maxmem and maxmem_frac (parameters that will need translating)
 */
struct ScryptParamsTranslate {
	double maxtime;
	double maxmemfrac;
	size_t maxmem;
	ScryptParams *params; //A pointer to a structure that holds the translated parameters

	ScryptParamsTranslate() : maxmemfrac(MAXMEMFRAC), maxmem(MAXMEM), params(NULL) {}
};
