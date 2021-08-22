package data

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/rubblelabs/ripple/crypto"
)

func Sign(s Signer, key crypto.Key, sequence *uint32) error {
	s.InitialiseForSigning()
	copy(s.GetPublicKey().Bytes(), key.Public(sequence))
	hash, msg, err := SigningHash(s)
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(key.Private(sequence), hash.Bytes(), append(s.SigningPrefix().Bytes(), msg...))
	if err != nil {
		return err
	}
	*s.GetSignature() = VariableLength(sig)
	hash, _, err = Raw(s)
	if err != nil {
		return err
	}
	copy(s.GetHash().Bytes(), hash.Bytes())
	return nil
}

func SignWithPrivKey(s Signer, key []byte) error {
	s.InitialiseForSigning()
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), key)
	copy(s.GetPublicKey().Bytes(), pubKey.SerializeCompressed())

	hash, msg, err := SigningHash(s)
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(privKey.Serialize(), hash.Bytes(), append(s.SigningPrefix().Bytes(), msg...))
	if err != nil {
		return err
	}
	*s.GetSignature() = VariableLength(sig)
	hash, _, err = Raw(s)
	if err != nil {
		return err
	}
	copy(s.GetHash().Bytes(), hash.Bytes())
	return nil
}

func CheckSignature(s Signer) (bool, error) {
	hash, msg, err := SigningHash(s)
	if err != nil {
		return false, err
	}
	return crypto.Verify(s.GetPublicKey().Bytes(), hash.Bytes(), msg, s.GetSignature().Bytes())
}
