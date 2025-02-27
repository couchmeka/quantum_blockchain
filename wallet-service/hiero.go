package main

import (
    "log"
)

type HieroPayment struct{}

func (hp *HieroPayment) ProcessPayment(amount float64) error {
    log.Printf("Processing Hiero payment for amount: %f", amount)
    return nil
}