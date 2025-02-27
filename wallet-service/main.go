package main

import (
    "fmt"
    "log"
)

type WalletService struct {
    solanaProcessor PaymentProcessor
    hieroProcessor PaymentProcessor
}

type PaymentProcessor interface {
    ProcessPayment(amount float64) error
}

func NewWalletService() *WalletService {
    return &WalletService{
        solanaProcessor: &SolanaPayment{},
        hieroProcessor: &HieroPayment{},
    }
}

func (ws *WalletService) ProcessPayment(walletType string, amount float64) error {
    switch walletType {
    case "solana":
        return ws.solanaProcessor.ProcessPayment(amount)
    case "hiero":
        return ws.hieroProcessor.ProcessPayment(amount)
    default:
        return fmt.Errorf("unsupported wallet type: %s", walletType)
    }
}

func main() {
    service := NewWalletService()
    log.Println("Wallet Service Started")

    // Example payment processing
    err := service.ProcessPayment("solana", 100.0)
    if err != nil {
        log.Printf("Error processing Solana payment: %v", err)
    }

    err = service.ProcessPayment("hiero", 50.0)
    if err != nil {
        log.Printf("Error processing Hiero payment: %v", err)
    }

    // Keep the service running
    select {}
}
