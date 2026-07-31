/* =============================
 * File: nonce_manager.h
 * Description: Public interface for a thread-safe nonce manager to prevent replay attacks.
 * ============================= */

#ifndef NONCE_MANAGER_H
#define NONCE_MANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include "auth_join.h"

#define NONCE_STORE_SIZE 256

/**
 * @brief Initializes the nonce manager module.
 * @details This must be called once at system startup before the module is used.
 */
void nonce_manager_init(void);

/**
 * @brief Checks if a nonce is valid and, if so, stores it.
 * @details This function is atomic. It checks if the given nonce is already in
 * the store. If not, it adds the nonce to the store and returns true.
 * If the nonce is already present (indicating a replay attack), it returns false.
 * @param nonce The hexadecimal string representation of the nonce to be validated.
 * @return true if the nonce is new and valid, false otherwise.
 */
bool nonce_is_valid_and_store(const char* nonce);

#endif // NONCE_MANAGER_H