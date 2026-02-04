package ethereumClient

import "github.com/ethereum/go-ethereum/ethclient"

func GetEthClient(rpcUrl string) (*ethclient.Client, error) {
	d, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, err
	}
	return d, nil
}
