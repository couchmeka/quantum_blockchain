package main

import (
    "log"
)

type SolanaPayment struct{}

func (sp *SolanaPayment) ProcessPayment(amount float64) error {
    log.Printf("Processing Solana payment for amount: %f", amount)
    return nil
}