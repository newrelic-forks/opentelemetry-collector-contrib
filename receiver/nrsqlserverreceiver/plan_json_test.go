// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func unmarshalFlatNodes(t *testing.T, obfuscatedXML string) []planFlatNode {
	t.Helper()
	result, err := xmlPlanToJSON(strings.TrimSpace(obfuscatedXML))
	require.NoError(t, err)
	require.NotEmpty(t, result)
	var nodes []planFlatNode
	require.NoError(t, json.Unmarshal([]byte(result), &nodes))
	return nodes
}

func TestXMLPlanToJSON_GoldenFile(t *testing.T) {
	obfuscatedXML, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	require.NoError(t, err)

	result, err := xmlPlanToJSON(strings.TrimSpace(string(obfuscatedXML)))
	require.NoError(t, err)

	expected, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlanJSON.json"))
	require.NoError(t, err)

	assert.JSONEq(t, strings.TrimSpace(string(expected)), result)
}

func TestXMLPlanToJSON_FlatArray(t *testing.T) {
	obfuscatedXML, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	require.NoError(t, err)

	nodes := unmarshalFlatNodes(t, string(obfuscatedXML))
	assert.Len(t, nodes, 4)
	for i, n := range nodes {
		assert.Equal(t, i+1, n.NodeID)
	}
}

func TestXMLPlanToJSON_RootNode(t *testing.T) {
	obfuscatedXML, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	require.NoError(t, err)

	nodes := unmarshalFlatNodes(t, string(obfuscatedXML))
	root := nodes[0]
	assert.Equal(t, 1, root.NodeID)
	assert.Equal(t, -1, root.ParentID)
	assert.Equal(t, "Root", root.InputType)
	assert.Equal(t, "Nested Loops", root.PhysicalOp)
	assert.Equal(t, "Inner Join", root.LogicalOp)
}

func TestXMLPlanToJSON_LeftRightInputType(t *testing.T) {
	obfuscatedXML, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	require.NoError(t, err)

	nodes := unmarshalFlatNodes(t, string(obfuscatedXML))
	assert.Equal(t, "LeftInput", nodes[1].InputType)
	assert.Equal(t, 1, nodes[1].ParentID)
	assert.Equal(t, "RightInput", nodes[3].InputType)
	assert.Equal(t, 1, nodes[3].ParentID)
}

func TestXMLPlanToJSON_RequiredAttributes(t *testing.T) {
	obfuscatedXML, err := os.ReadFile(filepath.Join("testdata", "expectedQueryPlan.xml"))
	require.NoError(t, err)

	nodes := unmarshalFlatNodes(t, string(obfuscatedXML))
	root := nodes[0]
	assert.NotEmpty(t, root.PhysicalOp)
	assert.NotEmpty(t, root.LogicalOp)
	assert.NotEmpty(t, root.EstimateRows)
	assert.NotEmpty(t, root.EstimatedTotalSubtreeCost)
	assert.NotEmpty(t, root.EstimateCPU)
	assert.NotEmpty(t, root.EstimateIO)
	assert.NotEmpty(t, root.AvgRowSize)
	assert.NotEmpty(t, root.EstimatedExecutionMode)
}

func TestXMLPlanToJSON_SchemaTableIndexFromIndexScan(t *testing.T) {
	plan := `<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan">
		<BatchSequence><Batch><Statements><StmtSimple><QueryPlan>
			<RelOp PhysicalOp="Index Scan" LogicalOp="Index Scan"
			       EstimateRows="500" EstimatedTotalSubtreeCost="0.03"
			       EstimateCPU="0.005" EstimateIO="0.025" AvgRowSize="30" EstimatedExecutionMode="Row">
				<IndexScan>
					<Object Schema="[dbo]" Table="[Orders]" Index="[IX_Orders_CustID]"/>
				</IndexScan>
			</RelOp>
		</QueryPlan></StmtSimple></Statements></Batch></BatchSequence>
	</ShowPlanXML>`

	nodes := unmarshalFlatNodes(t, plan)
	require.Len(t, nodes, 1)
	assert.Equal(t, "[dbo]", nodes[0].Schema)
	assert.Equal(t, "[Orders]", nodes[0].Table)
	assert.Equal(t, "[IX_Orders_CustID]", nodes[0].Index)
}

func TestXMLPlanToJSON_HashJoinLeftRight(t *testing.T) {
	plan := `<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan">
		<BatchSequence><Batch><Statements><StmtSimple><QueryPlan>
			<RelOp PhysicalOp="Hash Match" LogicalOp="Inner Join"
			       EstimateRows="100" EstimatedTotalSubtreeCost="0.05"
			       EstimateCPU="0.01" EstimateIO="0.0" AvgRowSize="50" EstimatedExecutionMode="Row">
				<Hash>
					<RelOp PhysicalOp="Index Scan" LogicalOp="Index Scan"
					       EstimateRows="500" EstimatedTotalSubtreeCost="0.03"
					       EstimateCPU="0.005" EstimateIO="0.025" AvgRowSize="30" EstimatedExecutionMode="Row">
						<IndexScan><Object Schema="[dbo]" Table="[Orders]" Index="[IX_CustID]"/></IndexScan>
					</RelOp>
					<RelOp PhysicalOp="Table Scan" LogicalOp="Table Scan"
					       EstimateRows="200" EstimatedTotalSubtreeCost="0.02"
					       EstimateCPU="0.003" EstimateIO="0.017" AvgRowSize="80" EstimatedExecutionMode="Row">
						<TableScan><Object Schema="[dbo]" Table="[Customers]"/></TableScan>
					</RelOp>
				</Hash>
			</RelOp>
		</QueryPlan></StmtSimple></Statements></Batch></BatchSequence>
	</ShowPlanXML>`

	nodes := unmarshalFlatNodes(t, plan)
	require.Len(t, nodes, 3)
	assert.Equal(t, "Root", nodes[0].InputType)
	assert.Equal(t, "LeftInput", nodes[1].InputType)
	assert.Equal(t, "[Orders]", nodes[1].Table)
	assert.Equal(t, "RightInput", nodes[2].InputType)
	assert.Equal(t, "[Customers]", nodes[2].Table)
}

func TestXMLPlanToJSON_Empty(t *testing.T) {
	result, err := xmlPlanToJSON("")
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestXMLPlanToJSON_InvalidXML(t *testing.T) {
	_, err := xmlPlanToJSON("<ShowPlanXML><Unclosed")
	assert.Error(t, err)
}

func TestXMLPlanToJSON_EmptyPlanReturnsEmptyArray(t *testing.T) {
	plan := `<ShowPlanXML xmlns="http://schemas.microsoft.com/sqlserver/2004/07/showplan">
		<BatchSequence><Batch><Statements></Statements></Batch></BatchSequence>
	</ShowPlanXML>`
	result, err := xmlPlanToJSON(plan)
	require.NoError(t, err)
	assert.Equal(t, "[]", result)
}
