package caller

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Layr-Labs/eigencompute-containers/eigenx-kms-client/pkg/types"
	appcontrollerV1 "github.com/Layr-Labs/eigenx-contracts/pkg/bindings/v1/AppController"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type ContractsConfig struct {
	AppControllerAddress common.Address
}

func (cc *ContractsConfig) Validate() error {
	if cc.AppControllerAddress == (common.Address{}) {
		return fmt.Errorf("AppControllerAddress cannot be zero address")
	}
	return nil
}

type ContractCaller struct {
	logger          *zap.Logger
	ethclient       *ethclient.Client
	contractsConfig *ContractsConfig
	appController   *appcontrollerV1.AppController
}

func NewContractCaller(ethclient *ethclient.Client, cfg *ContractsConfig, l *zap.Logger) (*ContractCaller, error) {
	if ethclient == nil {
		return nil, fmt.Errorf("ethclient cannot be nil")
	}
	if l == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	if cfg == nil {
		return nil, fmt.Errorf("ContractsConfig cannot be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid ContractsConfig: %w", err)
	}

	controllerCaller, err := appcontrollerV1.NewAppController(cfg.AppControllerAddress, ethclient)
	if err != nil {
		return nil, fmt.Errorf("failed to create AppController caller: %w", err)
	}

	return &ContractCaller{
		ethclient:       ethclient,
		contractsConfig: cfg,
		appController:   controllerCaller,
		logger:          l,
	}, nil
}

func (cc *ContractCaller) GetAppCreator(app common.Address, opts *bind.CallOpts) (common.Address, error) {
	creator, err := cc.appController.GetAppCreator(opts, app)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get app creator: %w", err)
	}
	return creator, nil
}

func (cc *ContractCaller) GetAppOperatorSetId(app common.Address, opts *bind.CallOpts) (uint32, error) {
	setId, err := cc.appController.GetAppOperatorSetId(opts, app)
	if err != nil {
		return 0, fmt.Errorf("failed to get app operator set ID: %w", err)
	}
	return setId, nil
}

func (cc *ContractCaller) GetAppLatestReleaseBlockNumber(app common.Address, opts *bind.CallOpts) (uint32, error) {
	blockNumber, err := cc.appController.GetAppLatestReleaseBlockNumber(opts, app)
	if err != nil {
		return 0, fmt.Errorf("failed to get app latest release block number: %w", err)
	}
	return blockNumber, nil
}

func (cc *ContractCaller) GetAppStatus(app common.Address, opts *bind.CallOpts) (uint8, error) {
	status, err := cc.appController.GetAppStatus(opts, app)
	if err != nil {
		return 0, fmt.Errorf("failed to get app status: %w", err)
	}
	return status, nil
}

func (cc *ContractCaller) FilterAppUpgraded(apps []common.Address, filterOpts *bind.FilterOpts) (*appcontrollerV1.AppControllerAppUpgradedIterator, error) {
	iterator, err := cc.appController.FilterAppUpgraded(filterOpts, apps)
	if err != nil {
		return nil, fmt.Errorf("failed to filter app upgraded events: %w", err)
	}
	return iterator, nil
}

func (cc *ContractCaller) GetLatestRelease(ctx context.Context, appID string) ([32]byte, types.Env, []byte, error) {
	cc.logger.Sugar().Debugw("Getting latest release", "app_id", appID)

	appAddress := common.HexToAddress(appID)
	cc.logger.Sugar().Debugw("Fetching app latest release block number", "app_address", appAddress)
	latestReleaseBlockNumber, err := cc.GetAppLatestReleaseBlockNumber(appAddress, &bind.CallOpts{Context: ctx})
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to get app latest release block number: %v", err)
	}
	cc.logger.Sugar().Debugw("App latest release block number fetched successfully", "block_number", latestReleaseBlockNumber)

	// get the latest release deployed at the block number
	releaseBlockNumberUint64 := uint64(latestReleaseBlockNumber)
	cc.logger.Sugar().Debug("Filtering app upgraded events", "block_number", releaseBlockNumberUint64, "app_address", appAddress)
	appUpgrades, err := cc.appController.FilterAppUpgraded(&bind.FilterOpts{Context: ctx, Start: releaseBlockNumberUint64, End: &releaseBlockNumberUint64}, []common.Address{appAddress})
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to filter app upgraded: %v", err)
	}
	cc.logger.Sugar().Debug("App upgraded events filtered successfully")

	// get the latest release deployed of all returned logs
	var lastAppUpgrade *appcontrollerV1.AppControllerAppUpgraded
	for appUpgrades.Next() {
		release := appUpgrades.Event
		if lastAppUpgrade == nil {
			lastAppUpgrade = release
		} else if release.Raw.Index > lastAppUpgrade.Raw.Index {
			lastAppUpgrade = release
		}
	}
	if lastAppUpgrade == nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("no app upgrade found for app %s at block %d", appID, releaseBlockNumberUint64)
	}

	release := lastAppUpgrade.Release
	cc.logger.Sugar().Debug("Found app upgraded event", "app_id", appID, "release_id", lastAppUpgrade.RmsReleaseId, "block", lastAppUpgrade.Raw.BlockNumber)

	if len(release.RmsRelease.Artifacts) != 1 {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("expected 1 artifact, got %d", len(release.RmsRelease.Artifacts))
	}
	cc.logger.Sugar().Debug("Release retrieved successfully", "app_id", appID, "artifact_digest", fmt.Sprintf("%x", release.RmsRelease.Artifacts[0].Digest))

	publicEnv := types.Env{}
	err = json.Unmarshal(release.PublicEnv, &publicEnv)
	if err != nil {
		return [32]byte{}, types.Env{}, nil, fmt.Errorf("failed to unmarshal env: %v", err)
	}
	cc.logger.Sugar().Debug("Latest release data prepared", "app_id", appID, "public_env_vars_count", len(publicEnv))

	return release.RmsRelease.Artifacts[0].Digest, publicEnv, release.EncryptedEnv, nil
}
