/**************************************************************************/
/*  RSA.cpp                                                               */
/**************************************************************************/
/*                         This file is part of:                          */
/*                             REDOT ENGINE                               */
/*                        https://redotengine.org                         */
/**************************************************************************/
/* Copyright (c) 2024-present Redot Engine contributors                   */
/*                                          (see REDOT_AUTHORS.md)        */
/* Copyright (c) 2014-present Godot Engine contributors (see AUTHORS.md). */
/* Copyright (c) 2007-2014 Juan Linietsky, Ariel Manzur.                  */
/*                                                                        */
/* Permission is hereby granted, free of charge, to any person obtaining  */
/* a copy of this software and associated documentation files (the        */
/* "Software"), to deal in the Software without restriction, including    */
/* without limitation the rights to use, copy, modify, merge, publish,    */
/* distribute, sublicense, and/or sell copies of the Software, and to     */
/* permit persons to whom the Software is furnished to do so, subject to  */
/* the following conditions:                                              */
/*                                                                        */
/* The above copyright notice and this permission notice shall be         */
/* included in all copies or substantial portions of the Software.        */
/*                                                                        */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. */
/* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY   */
/* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,   */
/* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE      */
/* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                 */
/**************************************************************************/

#include <ctime>
#include <iostream>

#include "../../thirdparty/gmp/gmp.h"
#include "../../thirdparty/gmp/gmpxx.h"
#include "RSA.h"

#define RSA_SIZE 1024 // (default:1024 - sets RSA to 2048 bit)
#define BASE 10

std::string rsa::generate_prime() {
	/*
	 * Generates and returns a large prime number
	 */

	std::string s;
	mpz_t i, j;
	mpz_class rng;

	mpz_init(i);
	mpz_init(j);

	gmp_randclass r(gmp_randinit_default);

	r.seed(std::rand());

	// Set bit size
	rng = r.get_z_bits(RSA_SIZE);

	// Grabs underlying mpz_t from mpz_class.
	mpz_set(i, rng.get_mpz_t());

	// Find the next prime of the given large value
	mpz_nextprime(j, i);

	// Set to return as a string
	s = mpz_get_str(NULL, BASE, j);

	// garbage collection
	mpz_clear(i);
	mpz_clear(j);

	return s;
}

std::string rsa::carmichael_fn(mpz_t p, mpz_t q, mpz_t one_tmp) {
	/*
	 * Obtains and returns co-prime:
	 *  phi = (p-1)(q-1)
	 */

	std::string s;

	mpz_t p_tmp, q_tmp, phi;

	mpz_init(p_tmp);
	mpz_init(q_tmp);
	mpz_init(phi);

	mpz_sub(p_tmp, p, one_tmp);
	mpz_sub(q_tmp, q, one_tmp);

	mpz_mul(phi, p_tmp, q_tmp);

	s = mpz_get_str(NULL, BASE, phi);

	mpz_clear(p_tmp);
	mpz_clear(q_tmp);
	mpz_clear(phi);

	return s;
}

void rsa::generate_keys() {
	/*
	 * Generates pubkey + privkey
	 */

	// Set seed
	std::srand(std::time(nullptr));

	mpz_t p, q, n, phi, e, d;
	mpz_t one_tmp;

	// init
	mpz_init(p); // Prime 1
	mpz_init(q); // Prime 2
	mpz_init(n); // Modulus
	mpz_init(phi); // lcd(lambda(p), lambda(q))
	mpz_init(e); // pubkey
	mpz_init(d); // privkey

	mpz_init(one_tmp); // mpz_t 1
	mpz_set_str(one_tmp, "1", BASE);

	// Can't return mpz_t because it's an array, so we do this:
	mpz_set_str(p, generate_prime().c_str(), BASE);
	mpz_set_str(q, generate_prime().c_str(), BASE);

	// Set modulus
	mpz_mul(n, p, q);

	// Carmichael function
	mpz_set_str(phi, carmichael_fn(p, q, one_tmp).c_str(), BASE);

	// Clear up memory
	mpz_clear(p);
	mpz_clear(q);

	// Generate pubkey
	mpz_sub(e, phi, one_tmp);
	mpz_prevprime(e, phi);

	// Generate privkey
	mpz_invert(d, e, phi);

	// Set keys + clear mem
	set_pubkey(mpz_get_str(NULL, 10, e));
	mpz_clear(e);

	set_privkey(mpz_get_str(NULL, 10, d));
	mpz_clear(d);

	set_modulus(mpz_get_str(NULL, 10, n));
	mpz_clear(n);
}

//void rsa::set_pubkey(mpz_t e)
void rsa::set_pubkey(std::string e) {
	/*
	 * Sets public key
	 */

	//mpz_set(public_key, e);
	public_key = e;
}

std::string rsa::get_pubkey() {
	/*
	 * Returns public key
	 */

	//return mpz_get_str(NULL, BASE, public_key);
	return public_key;
}

//void rsa::set_privkey(mpz_t d)
void rsa::set_privkey(std::string d) {
	/*
	 * Sets private key
	 */

	private_key = d;
	//mpz_set(private_key, d);
}

std::string rsa::get_privkey() {
	/*
	 * Returns private key
	 */

	//return mpz_get_str(NULL, BASE, private_key);
	return private_key;
}

void rsa::set_modulus(std::string n) {
	/*
	 * Sets modulus
	 */

	modulus = n;

	//mpz_set(modulus, n);
}

std::string rsa::get_modulus() {
	/*
	 * Returns modulus
	 */

	//return mpz_get_str(NULL, BASE, modulus);
	return modulus;
}

std::string rsa::encrypt(mpz_t msg) {
	/*
	 * Encrypt message.
	 */

	mpz_t e, pk, n;
	mpz_init(e);
	mpz_init(pk);
	mpz_init(n);
	std::string emsg;

	mpz_set_str(pk, get_pubkey().c_str(), BASE);
	mpz_set_str(n, get_modulus().c_str(), BASE);

	mpz_powm(e, msg, pk, n);
	mpz_clear(pk);
	mpz_clear(n);

	emsg = mpz_get_str(NULL, BASE, e);
	mpz_clear(e);

	return emsg;
}

std::string rsa::decrypt(mpz_t emsg) {
	/*
	 * Decrypt message.
	 */

	mpz_t d, pk, n;
	mpz_init(d);
	mpz_init(pk);
	mpz_init(n);
	std::string msg;

	mpz_set_str(pk, get_privkey().c_str(), BASE);
	mpz_set_str(n, get_modulus().c_str(), BASE);

	mpz_powm(d, emsg, pk, n);

	msg = mpz_get_str(NULL, BASE, d);
	mpz_clear(d);

	return msg;
}

void rsa::print() {
	/*
	 * This is simply testing to make sure things work.
	 * Don't bother using this after this module is completed.
	 */

	generate_keys();

	std::cout << "pubkey: " << get_pubkey() << std::endl;
	std::cout << "privkey: " << get_privkey() << std::endl;
	std::cout << "modulo: " << get_modulus() << std::endl;

	mpz_t msg;
	mpz_init(msg);
	mpz_set_ui(msg, 97); // ASCII: A

	std::cout << "plaintext: 97" << std::endl;

	// ENCRYPT MESSAGE:
	mpz_t encrypted_msg;
	mpz_init(encrypted_msg);
	mpz_set_str(encrypted_msg, encrypt(msg).c_str(), BASE);
	std::string enc_msg = mpz_get_str(NULL, BASE, encrypted_msg);

	std::cout << "encrypted: " << enc_msg << std::endl;

	mpz_t decrypted_msg;
	mpz_init(decrypted_msg);
	mpz_set_str(decrypted_msg, decrypt(encrypted_msg).c_str(), BASE);
	std::string dec_msg = mpz_get_str(NULL, BASE, decrypted_msg);

	std::cout << "decrypted: " << dec_msg << std::endl;
}

int main() {
	rsa rsa;

	rsa.print();

	return 0;
}
