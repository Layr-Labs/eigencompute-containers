package contractCaller

import (
	"context"

	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/types"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type IContractCaller interface {
	GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error)
	GetAppOperatorSetId(app common.Address, opts *bind.CallOpts) (uint32, error)
	GetAppLatestReleaseBlockNumber(app common.Address, opts *bind.CallOpts) (uint32, error)
	GetAppStatus(app common.Address, opts *bind.CallOpts) (uint8, error)
	GetLatestRelease(ctx context.Context, appID string) ([32]byte, types.Env, []byte, error)
}
