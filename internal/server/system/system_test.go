package system_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/blocky/nitriding/internal/server/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-ping/ping"
)

func TestGetFdLimit(t *testing.T) {
	soft, hard, err := system.GetFdLimit()
	assert.NoError(t, err)
	assert.Positive(t, soft)
	assert.Positive(t, hard)
}

func assertFdLimits(t *testing.T, soft uint64, hard uint64) {
	actualSoft, actualHard, err := system.GetFdLimit()
	require.NoError(t, err)
	assert.Equal(t, soft, actualSoft)
	assert.Equal(t, hard, actualHard)
}

func TestSetFdLimit(t *testing.T) {
	//We are using the default fd limit values in these tests,
	//so make sure that these are lower than the current process settings,
	//since increasing the file descriptor limit of a process causes an error.
	startingSoft, startingHard, err := system.GetFdLimit()
	require.NoError(t, err)
	require.Less(t, system.DefaultFdSoft, startingSoft)
	require.Less(t, system.DefaultFdHard, startingHard)

	//These tests need to execute serially,
	//to avoid race conditions on the shared system resource of file
	//descriptor limit. These tests also need to execute in order since
	//increasing a file descriptor limit of a processes causes an error,
	//hence the uses of lock.Lock() outside of t.Run calls.
	var lock = sync.Mutex{}

	lock.Lock()
	t.Run("cannot increase limit", func(t *testing.T) {
		defer lock.Unlock()
		err = system.SetFdLimit(startingSoft+1, startingHard+1)
		assert.ErrorContains(t, err, system.ErrSetFdLimit)
	})

	lock.Lock()
	t.Run("happy path: set limits to value", func(t *testing.T) {
		defer lock.Unlock()
		err := system.SetFdLimit(system.DefaultFdSoft+1, system.DefaultFdHard+1)
		assert.NoError(t, err)
		assertFdLimits(t, system.DefaultFdSoft+1, system.DefaultFdHard+1)
	})
	lock.Lock()
	t.Run("happy path: set limits to 0", func(t *testing.T) {
		defer lock.Unlock()
		err := system.SetFdLimit(0, 0)
		assert.NoError(t, err)
		assertFdLimits(t, system.DefaultFdSoft, system.DefaultFdHard)
	})

	lock.Lock()
	t.Run("hard < default soft", func(t *testing.T) {
		defer lock.Unlock()
		err := system.SetFdLimit(0, 1)
		assert.ErrorContains(t, err, system.ErrMaxFdLimitLowerThanSoft)
	})

	lock.Lock()
	t.Run("hard < soft", func(t *testing.T) {
		defer lock.Unlock()
		err := system.SetFdLimit(system.DefaultFdSoft, system.DefaultFdSoft-1)
		assert.ErrorContains(t, err, system.ErrMaxFdLimitLowerThanSoft)
	})
}

func TestAssignLoAddr(t *testing.T) {
	err := system.AssignLoAddr()
	if err != nil &&
		strings.Contains(err.Error(), system.ErrLinkIP) &&
		strings.Contains(err.Error(), "file exists") {
		t.Logf(
			"mapping from %v to the loopback interface already exists",
			system.LocalHostAddr,
		)
	} else if err != nil &&
		strings.Contains(err.Error(), system.ErrLinkIP) &&
		strings.Contains(err.Error(), "operation not permitted") {
		t.Logf("interface assignment operation not permitted"+
			" - may want to run in sudo\n"+
			"Checking if %v is assigned to the loopback interface anyway",
			system.LocalHostAddr,
		)

		pinger, err := ping.NewPinger(system.LocalHostAddr)
		assert.NoError(t, err)
		pinger.Count = 1
		err = pinger.Run()
		require.NoError(t, err)
		t.Logf(
			"%v is assigned to the loopback interface",
			system.LocalHostAddr,
		)
	} else {
		require.NoError(t, err)
	}

}
