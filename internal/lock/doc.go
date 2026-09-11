// Package lock holds the records and signatures of the network lock
// (spec 012): an Ed25519 lock key on a device the owner controls signs
// each peer record, the server stores and forwards the signatures, and
// a client with the lock enabled applies only signed peers.
//
// The package implements no cryptography. It encodes records into a
// fixed canonical byte form and calls crypto/ed25519 to sign and verify
// them.
package lock
