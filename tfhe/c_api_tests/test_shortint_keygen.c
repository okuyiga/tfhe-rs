#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_predefined_keygen_w_serde(void) {
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintParameters *params = NULL;
  ShortintCiphertext *ct = NULL;
  Buffer ct_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintCiphertext *deser_ct = NULL;
  ShortintCompressedCiphertext *cct = NULL;
  ShortintCompressedCiphertext *deser_cct = NULL;
  ShortintCiphertext *decompressed_ct = NULL;

  int get_params_ok = shortint_get_parameters(2, 2, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortint_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int encrypt_ok = shortint_client_key_encrypt(cks, 3, &ct);
  assert(encrypt_ok == 0);

  int ser_ok = shortint_serialize_ciphertext(ct, &ct_ser_buffer);
  assert(ser_ok == 0);

  BufferView deser_view = {.pointer = ct_ser_buffer.pointer, .length = ct_ser_buffer.length};

  int deser_ok = shortint_deserialize_ciphertext(deser_view, &deser_ct);
  assert(deser_ok == 0);

  assert(deser_view.length == ct_ser_buffer.length);
  for (size_t idx = 0; idx < deser_view.length; ++idx) {
    assert(deser_view.pointer[idx] == ct_ser_buffer.pointer[idx]);
  }

  uint64_t result = -1;
  int decrypt_ok = shortint_client_key_decrypt(cks, deser_ct, &result);
  assert(decrypt_ok == 0);

  assert(result == 3);

  int c_encrypt_ok = shortint_client_key_encrypt_compressed(cks, 3, &cct);
  assert(c_encrypt_ok == 0);

  int c_ser_ok = shortint_serialize_compressed_ciphertext(cct, &ct_ser_buffer);
  assert(c_ser_ok == 0);

  deser_view.pointer = ct_ser_buffer.pointer;
  deser_view.length = ct_ser_buffer.length;

  int c_deser_ok = shortint_deserialize_compressed_ciphertext(deser_view, &deser_cct);
  assert(c_deser_ok == 0);

  int decomp_ok = shortint_decompress_ciphertext(cct, &decompressed_ct);
  assert(decomp_ok == 0);

  uint64_t c_result = -1;
  int c_decrypt_ok = shortint_client_key_decrypt(cks, decompressed_ct, &c_result);
  assert(c_decrypt_ok == 0);

  assert(c_result == 3);

  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
  destroy_shortint_parameters(params);
  destroy_shortint_ciphertext(ct);
  destroy_shortint_ciphertext(deser_ct);
  destroy_shortint_compressed_ciphertext(cct);
  destroy_shortint_compressed_ciphertext(deser_cct);
  destroy_shortint_ciphertext(decompressed_ct);
  destroy_buffer(&ct_ser_buffer);
}

void test_server_key_trivial_encrypt(void) {
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintParameters *params = NULL;
  ShortintCiphertext *ct = NULL;

  int get_params_ok = shortint_get_parameters(2, 2, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortint_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int encrypt_ok = shortint_server_key_create_trivial(sks, 3, &ct);
  assert(encrypt_ok == 0);

  uint64_t result = -1;
  int decrypt_ok = shortint_client_key_decrypt(cks, ct, &result);
  assert(decrypt_ok == 0);

  assert(result == 3);

  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
  destroy_shortint_parameters(params);
  destroy_shortint_ciphertext(ct);
}

void test_custom_keygen(void) {
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintParameters *params = NULL;

  int params_ok = shortint_create_parameters(10, 1, 1024, 10e-100, 10e-100, 2, 3, 2, 3, 2, 3,
                                             10e-100, 2, 3, 2, 2, &params);
  assert(params_ok == 0);

  int gen_keys_ok = shortint_gen_keys_with_parameters(params, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_shortint_parameters(params);
  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
}

void test_public_keygen(void) {
  ShortintClientKey *cks = NULL;
  ShortintPublicKey *pks = NULL;
  ShortintPublicKey *pks_deser = NULL;
  ShortintParameters *params = NULL;
  ShortintCiphertext *ct = NULL;
  Buffer pks_ser_buff = {.pointer = NULL, .length = 0};

  int get_params_ok = shortint_get_parameters(2, 2, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortint_gen_client_key(params, &cks);
  assert(gen_keys_ok == 0);

  int gen_pks = shortint_gen_public_key(cks, &pks);
  assert(gen_pks == 0);

  int pks_ser = shortint_serialize_public_key(pks, &pks_ser_buff);
  assert(pks_ser == 0);

  BufferView pks_ser_buff_view = {.pointer = pks_ser_buff.pointer, .length = pks_ser_buff.length};
  int pks_deser_ok = shortint_deserialize_public_key(pks_ser_buff_view, &pks_deser);
  assert(pks_deser_ok == 0);

  uint64_t msg = 2;

  int encrypt_ok = shortint_public_key_encrypt(pks_deser, msg, &ct);
  assert(encrypt_ok == 0);

  uint64_t result = -1;
  int decrypt_ok = shortint_client_key_decrypt(cks, ct, &result);
  assert(decrypt_ok == 0);

  assert(result == 2);

  destroy_shortint_parameters(params);
  destroy_shortint_client_key(cks);
  destroy_shortint_public_key(pks);
  destroy_shortint_public_key(pks_deser);
  destroy_buffer(&pks_ser_buff);
  destroy_shortint_ciphertext(ct);
}

void test_compressed_public_keygen(void) {
  ShortintClientKey *cks = NULL;
  ShortintCompressedPublicKey *cpks = NULL;
  ShortintPublicKey *pks = NULL;
  ShortintParameters *params = NULL;
  ShortintCiphertext *ct = NULL;

  int get_params_ok = shortint_get_parameters(2, 2, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortint_gen_client_key(params, &cks);
  assert(gen_keys_ok == 0);

  int gen_cpks = shortint_gen_compressed_public_key(cks, &cpks);
  assert(gen_cpks == 0);

  uint64_t msg = 2;

  int encrypt_compressed_ok = shortint_compressed_public_key_encrypt(cpks, msg, &ct);
  assert(encrypt_compressed_ok == 0);

  uint64_t result_compressed = -1;
  int decrypt_compressed_ok = shortint_client_key_decrypt(cks, ct, &result_compressed);
  assert(decrypt_compressed_ok == 0);

  assert(result_compressed == 2);

  int decompress_ok = shortint_decompress_public_key(cpks, &pks);
  assert(decompress_ok == 0);

  int encrypt_ok = shortint_public_key_encrypt(pks, msg, &ct);
  assert(encrypt_ok == 0);

  uint64_t result = -1;
  int decrypt_ok = shortint_client_key_decrypt(cks, ct, &result);
  assert(decrypt_ok == 0);

  assert(result == 2);

  destroy_shortint_parameters(params);
  destroy_shortint_client_key(cks);
  destroy_shortint_compressed_public_key(cpks);
  destroy_shortint_public_key(pks);
  destroy_shortint_ciphertext(ct);
}

int main(void) {
  test_predefined_keygen_w_serde();
  test_custom_keygen();
  test_public_keygen();
  test_compressed_public_keygen();
  test_server_key_trivial_encrypt();
  return EXIT_SUCCESS;
}
