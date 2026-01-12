package contractCaller

import (
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type Env map[string]string

type IContractCaller interface {
	GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error)
	GetAppOperatorSetId(app common.Address, opts *bind.CallOpts) (uint32, error)
	GetAppLatestReleaseBlockNumber(app common.Address, opts *bind.CallOpts) (uint32, error)
	GetAppStatus(app common.Address, opts *bind.CallOpts) (uint8, error)
}
