"""
Тесты криптографических примитивов ShadowTunnel.
"""

import os
import pytest
from hypothesis import given, strategies as st

from shared.crypto import ShadowCrypto, CryptoError
from shared.constants import AES_KEY_SIZE, HMAC_SIZE, AES_NONCE_SIZE


class TestKeyGeneration:
    """Тесты генерации ключей."""

    def test_identity_keypair_generation(self):
        """Ed25519 ключи генерируются без ошибок."""
        private_key, public_key = ShadowCrypto.generate_identity_keypair()
        assert private_key is not None
        assert public_key is not None

    def test_ephemeral_keypair_generation(self):
        """X25519 эфемерные ключи генерируются без ошибок."""
        private_key, public_key = ShadowCrypto.generate_ephemeral_keypair()
        assert private_key is not None
        assert public_key is not None

    def test_identity_key_serialization_roundtrip(self):
        """Сериализация и десериализация Ed25519 ключей."""
        private_key, public_key = ShadowCrypto.generate_identity_keypair()
        
        priv_bytes = ShadowCrypto.serialize_private_key(private_key)
        pub_bytes = ShadowCrypto.serialize_public_key(public_key)
        
        priv_restored = ShadowCrypto.deserialize_private_key(priv_bytes)
        pub_restored = ShadowCrypto.deserialize_public_key(pub_bytes)
        
        assert priv_restored is not None
        assert pub_restored is not None

    def test_x25519_public_key_roundtrip(self):
        """Экспорт/импорт X25519 публичного ключа."""
        _, pub = ShadowCrypto.generate_ephemeral_keypair()
        raw = ShadowCrypto.export_x25519_public(pub)
        
        assert len(raw) == 32
        
        restored = ShadowCrypto.import_x25519_public(raw)
        assert ShadowCrypto.export_x25519_public(restored) == raw

    def test_challenge_generation(self):
        """Challenge генерируется с правильным размером."""
        challenge = ShadowCrypto.generate_challenge()
        assert len(challenge) == 32

    def test_challenges_are_unique(self):
        """Два challenge не совпадают."""
        c1 = ShadowCrypto.generate_challenge()
        c2 = ShadowCrypto.generate_challenge()
        assert c1 != c2


class TestECDH:
    """Тесты обмена ключами ECDH."""

    def test_ecdh_shared_secret(self):
        """ECDH даёт одинаковый shared secret на обеих сторонах."""
        crypto_a = ShadowCrypto()
        crypto_b = ShadowCrypto()
        
        priv_a, pub_a = ShadowCrypto.generate_ephemeral_keypair()
        priv_b, pub_b = ShadowCrypto.generate_ephemeral_keypair()
        
        derived_a = crypto_a.perform_ecdh(priv_a, pub_b)
        derived_b = crypto_b.perform_ecdh(priv_b, pub_a)
        
        assert derived_a == derived_b
        assert len(derived_a) == AES_KEY_SIZE + HMAC_SIZE

    def test_ecdh_sets_session_keys(self):
        """ECDH устанавливает сессионные ключи."""
        crypto = ShadowCrypto()
        priv_a, pub_a = ShadowCrypto.generate_ephemeral_keypair()
        priv_b, pub_b = ShadowCrypto.generate_ephemeral_keypair()
        
        crypto.perform_ecdh(priv_a, pub_b)
        
        assert crypto.has_session_keys
        assert crypto.session_key is not None
        assert crypto.hmac_key is not None
        assert len(crypto.session_key) == AES_KEY_SIZE
        assert len(crypto.hmac_key) == HMAC_SIZE


class TestAESGCM:
    """Тесты шифрования AES-256-GCM."""

    def setup_method(self):
        """Устанавливаем сессионные ключи перед каждым тестом."""
        self.crypto = ShadowCrypto()
        self.crypto.set_session_keys(
            os.urandom(AES_KEY_SIZE),
            os.urandom(HMAC_SIZE),
        )

    def test_encrypt_decrypt_roundtrip(self):
        """Шифрование и дешифрование возвращают оригинальные данные."""
        plaintext = b"Hello, ShadowTunnel!"
        nonce, ciphertext = self.crypto.encrypt(plaintext)
        
        assert ciphertext != plaintext
        assert len(nonce) == AES_NONCE_SIZE
        
        decrypted = self.crypto.decrypt(nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_with_aad(self):
        """Шифрование/дешифрование с AAD."""
        plaintext = b"Secret data"
        aad = b"session-id-12345"
        
        nonce, ciphertext = self.crypto.encrypt(plaintext, aad)
        decrypted = self.crypto.decrypt(nonce, ciphertext, aad)
        
        assert decrypted == plaintext

    def test_wrong_aad_fails(self):
        """Неверный AAD при дешифровании вызывает ошибку."""
        plaintext = b"Secret data"
        aad = b"correct-aad"
        
        nonce, ciphertext = self.crypto.encrypt(plaintext, aad)
        
        with pytest.raises(CryptoError):
            self.crypto.decrypt(nonce, ciphertext, b"wrong-aad")

    def test_tampered_ciphertext_fails(self):
        """Изменённый ciphertext не дешифруется."""
        plaintext = b"Important data"
        nonce, ciphertext = self.crypto.encrypt(plaintext)
        
        # Модифицируем ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        
        with pytest.raises(CryptoError):
            self.crypto.decrypt(nonce, bytes(tampered))

    def test_wrong_nonce_fails(self):
        """Неверный nonce не дешифрует данные."""
        plaintext = b"Test data"
        nonce, ciphertext = self.crypto.encrypt(plaintext)
        
        wrong_nonce = os.urandom(AES_NONCE_SIZE)
        
        with pytest.raises(CryptoError):
            self.crypto.decrypt(wrong_nonce, ciphertext)

    @given(data=st.binary(min_size=1, max_size=1400))
    def test_encrypt_decrypt_arbitrary_data(self, data):
        """Произвольные данные шифруются/дешифруются корректно (fuzz)."""
        nonce, ct = self.crypto.encrypt(data)
        assert self.crypto.decrypt(nonce, ct) == data

    def test_empty_plaintext(self):
        """Пустые данные шифруются/дешифруются."""
        nonce, ct = self.crypto.encrypt(b"")
        assert self.crypto.decrypt(nonce, ct) == b""

    def test_encrypt_without_session_keys_fails(self):
        """Шифрование без сессионных ключей вызывает ошибку."""
        crypto = ShadowCrypto()
        with pytest.raises(CryptoError):
            crypto.encrypt(b"data")


class TestSignatures:
    """Тесты подписей Ed25519."""

    def test_sign_verify(self):
        """Подпись верифицируется корректно."""
        private_key, public_key = ShadowCrypto.generate_identity_keypair()
        data = b"Message to sign"
        
        signature = ShadowCrypto.sign(private_key, data)
        
        assert len(signature) == 64
        assert ShadowCrypto.verify_signature(public_key, signature, data)

    def test_wrong_key_fails_verification(self):
        """Подпись не верифицируется чужим ключом."""
        priv1, _ = ShadowCrypto.generate_identity_keypair()
        _, pub2 = ShadowCrypto.generate_identity_keypair()
        
        data = b"Signed message"
        signature = ShadowCrypto.sign(priv1, data)
        
        assert not ShadowCrypto.verify_signature(pub2, signature, data)

    def test_tampered_data_fails_verification(self):
        """Изменённые данные не проходят проверку подписи."""
        private_key, public_key = ShadowCrypto.generate_identity_keypair()
        data = b"Original message"
        
        signature = ShadowCrypto.sign(private_key, data)
        
        assert not ShadowCrypto.verify_signature(public_key, signature, b"Modified message")


class TestHMAC:
    """Тесты HMAC-SHA256."""

    def setup_method(self):
        self.crypto = ShadowCrypto()
        self.crypto.set_session_keys(
            os.urandom(AES_KEY_SIZE),
            os.urandom(HMAC_SIZE),
        )

    def test_hmac_compute_verify(self):
        """HMAC вычисляется и верифицируется."""
        data = b"Packet data"
        hmac_value = self.crypto.compute_hmac(data)
        
        assert len(hmac_value) == 32
        assert self.crypto.verify_hmac(data, hmac_value)

    def test_wrong_hmac_fails(self):
        """Неверный HMAC не проходит проверку."""
        data = b"Packet data"
        wrong_hmac = os.urandom(32)
        
        assert not self.crypto.verify_hmac(data, wrong_hmac)

    def test_hmac_without_key_fails(self):
        """HMAC без ключа вызывает ошибку."""
        crypto = ShadowCrypto()
        with pytest.raises(CryptoError):
            crypto.compute_hmac(b"data")


class TestKeyRotation:
    """Тесты ротации ключей."""

    def test_key_rotation_changes_keys(self):
        """Ротация изменяет ключи."""
        crypto = ShadowCrypto()
        crypto.set_session_keys(os.urandom(AES_KEY_SIZE), os.urandom(HMAC_SIZE))
        
        old_session = crypto.session_key
        old_hmac = crypto.hmac_key
        
        crypto.derive_rotation_keys(old_session, rotation_counter=1)
        
        assert crypto.session_key != old_session
        assert crypto.hmac_key != old_hmac

    def test_key_rotation_produces_valid_keys(self):
        """Новые ключи после ротации работают."""
        crypto = ShadowCrypto()
        crypto.set_session_keys(os.urandom(AES_KEY_SIZE), os.urandom(HMAC_SIZE))
        
        crypto.derive_rotation_keys(crypto.session_key, 1)
        
        # Проверяем, что шифрование работает с новыми ключами
        plaintext = b"Test after rotation"
        nonce, ct = crypto.encrypt(plaintext)
        assert crypto.decrypt(nonce, ct) == plaintext

    def test_clear_keys(self):
        """Очистка ключей удаляет их из памяти."""
        crypto = ShadowCrypto()
        crypto.set_session_keys(os.urandom(AES_KEY_SIZE), os.urandom(HMAC_SIZE))
        
        assert crypto.has_session_keys
        
        crypto.clear_keys()
        
        assert not crypto.has_session_keys
        assert crypto.session_key is None
        assert crypto.hmac_key is None
