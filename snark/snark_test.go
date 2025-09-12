package snark

import "testing"

func BenchmarkProve(b *testing.B) {
	cs, pk, _, skBI := setup(1)
	b.ResetTimer()
	for b.Loop() {
		prove(skBI, pk, cs)
	}
}

func BenchmarkVerify(b *testing.B) {
	cs, pk, vk, skBI := setup(1)
	pi, proof := prove(skBI, pk, cs)
	b.ResetTimer()
	for b.Loop() {
		verify(proof, vk, pi, cs)
	}
}
