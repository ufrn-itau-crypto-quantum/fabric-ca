package lib

import (
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistryAttrCasePreserved pins the spelling of the registry attribute names against
// viper, which lowercases every key it unmarshals.
//
// Fabric matches attribute names literally, so a lowercased "hf.Registrar.Roles" makes the
// bootstrap admin stop being a registrar.
func TestRegistryAttrCasePreserved(t *testing.T) {
	yaml := `
registry:
  identities:
     - name: admin
       pass: adminpw
       type: admin
       affiliation: ""
       attrs:
          hf.Registrar.Roles: "*"
          hf.Registrar.DelegateRoles: "*"
          hf.Revoker: true
          hf.IntermediateCA: true
          hf.GenCRL: true
          hf.Registrar.Attributes: "*"
          hf.AffiliationMgr: true
`
	f, err := os.CreateTemp("", "*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(yaml)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	defer os.Remove(f.Name())

	cfg := &ServerConfig{}
	require.NoError(t, UnmarshalConfig(cfg, viper.New(), f.Name(), true))

	identities := cfg.CAcfg.Registry.Identities
	require.Len(t, identities, 1)

	for _, name := range []string{
		"hf.Registrar.Roles",
		"hf.Registrar.DelegateRoles",
		"hf.Revoker",
		"hf.IntermediateCA",
		"hf.GenCRL",
		"hf.Registrar.Attributes",
		"hf.AffiliationMgr",
	} {
		assert.Contains(t, identities[0].Attrs, name)
	}
	assert.NotContains(t, identities[0].Attrs, "hf.registrar.roles")
	assert.Equal(t, "*", identities[0].Attrs["hf.Registrar.Roles"])
}
