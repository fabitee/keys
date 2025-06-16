package keys_test

import (
	"testing"

	"github.com/fabitee/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	rsa, err := keys.GatewayPublic.GetRSA()
	require.NoError(t, err)
	assert.NotZero(t, rsa.Size())
}
