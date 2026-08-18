// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nrsqlserverreceiver // import "github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver"

import (
	"encoding/json"
	"encoding/xml"

	"github.com/newrelic-forks/opentelemetry-collector-contrib/receiver/nrsqlserverreceiver/internal/metadata"
)

// planFlatNode is one operator node in the flat JSON array emitted for a SQL Server execution plan.
// The frontend rebuilds the tree from node_id + parent_id + input_type.
type planFlatNode struct {
	NodeID                    int    `json:"node_id"`
	ParentID                  int    `json:"parent_id"`
	InputType                 string `json:"input_type"`
	PhysicalOp                string `json:"physical_op,omitempty"`
	LogicalOp                 string `json:"logical_op,omitempty"`
	EstimateRows              string `json:"estimate_rows,omitempty"`
	EstimatedTotalSubtreeCost string `json:"estimated_total_subtree_cost,omitempty"`
	EstimateCPU               string `json:"estimate_cpu,omitempty"`
	EstimateIO                string `json:"estimate_io,omitempty"`
	AvgRowSize                string `json:"avg_row_size,omitempty"`
	EstimatedExecutionMode    string `json:"estimated_execution_mode,omitempty"`
	Schema                    string `json:"schema,omitempty"`
	Table                     string `json:"table,omitempty"`
	Index                     string `json:"index,omitempty"`
}

// --- minimal XML struct types for SQL Server ShowPlan XML ---

type xmlShowPlan struct {
	BatchSequence []xmlBatchSequence `xml:"BatchSequence"`
}

type xmlBatchSequence struct {
	Batches []xmlBatch `xml:"Batch"`
}

type xmlBatch struct {
	Statements []xmlStmtSimple `xml:"Statements>StmtSimple"`
}

type xmlStmtSimple struct {
	QueryPlan xmlQueryPlan `xml:"QueryPlan"`
}

type xmlQueryPlan struct {
	Root xmlRelOp `xml:"RelOp"`
}

type xmlRelOp struct {
	// 8 UI-required attributes on RelOp
	PhysicalOp                string `xml:"PhysicalOp,attr"`
	LogicalOp                 string `xml:"LogicalOp,attr"`
	EstimateRows              string `xml:"EstimateRows,attr"`
	EstimatedTotalSubtreeCost string `xml:"EstimatedTotalSubtreeCost,attr"`
	EstimateCPU               string `xml:"EstimateCPU,attr"`
	EstimateIO                string `xml:"EstimateIO,attr"`
	AvgRowSize                string `xml:"AvgRowSize,attr"`
	EstimatedExecutionMode    string `xml:"EstimatedExecutionMode,attr"`

	// Explicit left/right sides present in some plan formats
	OneSide   *xmlRelOp `xml:"OneSide>RelOp"`
	OtherSide *xmlRelOp `xml:"OtherSide>RelOp"`

	// Leaf operators — Schema/Table/Index live on their nested Object element
	IndexScan *xmlIndexScan `xml:"IndexScan"`
	TableScan *xmlTableScan `xml:"TableScan"`

	// Binary join operators: first child = LeftInput, second = RightInput
	NestedLoops *xmlOpChildren `xml:"NestedLoops"`
	Hash        *xmlOpChildren `xml:"Hash"`
	Merge       *xmlOpChildren `xml:"Merge"`

	// Single-input operators
	Filter          *xmlOpChildren `xml:"Filter"`
	Sort            *xmlOpChildren `xml:"Sort"`
	ComputeScalar   *xmlOpChildren `xml:"ComputeScalar"`
	StreamAggregate *xmlOpChildren `xml:"StreamAggregate"`
	Concatenation   *xmlOpChildren `xml:"Concatenation"`
	Parallelism     *xmlOpChildren `xml:"Parallelism"`

	// Direct RelOp children — catch-all for operator types not listed above
	RelOp []xmlRelOp `xml:"RelOp"`
}

type xmlIndexScan struct {
	Object *xmlObject `xml:"Object"`
	RelOp  []xmlRelOp `xml:"RelOp"`
}

type xmlTableScan struct {
	Object *xmlObject `xml:"Object"`
	RelOp  []xmlRelOp `xml:"RelOp"`
}

type xmlObject struct {
	Schema string `xml:"Schema,attr"`
	Table  string `xml:"Table,attr"`
	Index  string `xml:"Index,attr"`
}

// xmlOpChildren is shared by all operator elements that only carry child RelOp nodes.
type xmlOpChildren struct {
	RelOp []xmlRelOp `xml:"RelOp"`
}

// xmlPlanToNodes parses an obfuscated XML execution plan and returns a flat slice of
// planFlatNode — one entry per RelOp operator in the plan.
// The input must be the output of obfuscateXMLPlan (already-obfuscated XML).
// Returns a nil slice (no error) when the input is empty.
func xmlPlanToNodes(obfuscatedXML string) ([]planFlatNode, error) {
	if obfuscatedXML == "" {
		return nil, nil
	}

	var plan xmlShowPlan
	if err := xml.Unmarshal([]byte(obfuscatedXML), &plan); err != nil {
		return nil, err
	}

	nodes := make([]planFlatNode, 0)
	counter := 0
	for i := range plan.BatchSequence {
		for j := range plan.BatchSequence[i].Batches {
			for k := range plan.BatchSequence[i].Batches[j].Statements {
				root := &plan.BatchSequence[i].Batches[j].Statements[k].QueryPlan.Root
				walkRelOp(root, &nodes, &counter, -1, "Root")
			}
		}
	}
	return nodes, nil
}

// xmlPlanToJSON converts an obfuscated XML execution plan to a compact JSON array of
// operator nodes. Kept for tests; the scraper uses xmlPlanToNodes directly.
func xmlPlanToJSON(obfuscatedXML string) (string, error) {
	if obfuscatedXML == "" {
		return "", nil
	}

	var plan xmlShowPlan
	if err := xml.Unmarshal([]byte(obfuscatedXML), &plan); err != nil {
		return "", err
	}

	nodes := make([]planFlatNode, 0)
	counter := 0

	for i := range plan.BatchSequence {
		for j := range plan.BatchSequence[i].Batches {
			for k := range plan.BatchSequence[i].Batches[j].Statements {
				root := &plan.BatchSequence[i].Batches[j].Statements[k].QueryPlan.Root
				walkRelOp(root, &nodes, &counter, -1, "Root")
			}
		}
	}

	out, err := json.Marshal(nodes)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// walkRelOp appends a planFlatNode for op and recurses into its children.
func walkRelOp(op *xmlRelOp, nodes *[]planFlatNode, counter *int, parentID int, inputType string) {
	if op == nil {
		return
	}
	*counter++
	currentID := *counter

	node := planFlatNode{
		NodeID:                    currentID,
		ParentID:                  parentID,
		InputType:                 inputType,
		PhysicalOp:                op.PhysicalOp,
		LogicalOp:                 op.LogicalOp,
		EstimateRows:              op.EstimateRows,
		EstimatedTotalSubtreeCost: op.EstimatedTotalSubtreeCost,
		EstimateCPU:               op.EstimateCPU,
		EstimateIO:                op.EstimateIO,
		AvgRowSize:                op.AvgRowSize,
		EstimatedExecutionMode:    op.EstimatedExecutionMode,
	}

	if op.IndexScan != nil && op.IndexScan.Object != nil {
		node.Schema = op.IndexScan.Object.Schema
		node.Table = op.IndexScan.Object.Table
		node.Index = op.IndexScan.Object.Index
	} else if op.TableScan != nil && op.TableScan.Object != nil {
		node.Schema = op.TableScan.Object.Schema
		node.Table = op.TableScan.Object.Table
	}

	*nodes = append(*nodes, node)

	// Explicit left/right — takes precedence over operator-level children
	walkRelOp(op.OneSide, nodes, counter, currentID, "LeftInput")
	walkRelOp(op.OtherSide, nodes, counter, currentID, "RightInput")

	// Binary join operators: first child = LeftInput, second = RightInput
	walkBinary(op.NestedLoops, nodes, counter, currentID)
	walkBinary(op.Hash, nodes, counter, currentID)
	walkBinary(op.Merge, nodes, counter, currentID)

	// Single-input operators
	walkSingle(op.Filter, nodes, counter, currentID)
	walkSingle(op.Sort, nodes, counter, currentID)
	walkSingle(op.ComputeScalar, nodes, counter, currentID)
	walkSingle(op.StreamAggregate, nodes, counter, currentID)
	walkSingle(op.Concatenation, nodes, counter, currentID)
	walkSingle(op.Parallelism, nodes, counter, currentID)

	// Leaf operator children (unusual but possible in some plan shapes)
	if op.IndexScan != nil {
		for i := range op.IndexScan.RelOp {
			walkRelOp(&op.IndexScan.RelOp[i], nodes, counter, currentID, "Input")
		}
	}
	if op.TableScan != nil {
		for i := range op.TableScan.RelOp {
			walkRelOp(&op.TableScan.RelOp[i], nodes, counter, currentID, "Input")
		}
	}

	// Direct RelOp children — catch-all for operator types not explicitly listed above
	for i := range op.RelOp {
		walkRelOp(&op.RelOp[i], nodes, counter, currentID, "Input")
	}
}

// walkBinary recurses into children of a binary join operator, tagging the first child
// as LeftInput and the second as RightInput.
func walkBinary(op *xmlOpChildren, nodes *[]planFlatNode, counter *int, parentID int) {
	if op == nil {
		return
	}
	for i := range op.RelOp {
		inputType := "Input"
		switch i {
		case 0:
			inputType = "LeftInput"
		case 1:
			inputType = "RightInput"
		}
		walkRelOp(&op.RelOp[i], nodes, counter, parentID, inputType)
	}
}

// walkSingle recurses into children of a single-input operator.
func walkSingle(op *xmlOpChildren, nodes *[]planFlatNode, counter *int, parentID int) {
	if op == nil {
		return
	}
	for i := range op.RelOp {
		walkRelOp(&op.RelOp[i], nodes, counter, parentID, "Input")
	}
}

// inputTypeAttr converts the InputType string to the generated enum value.
func inputTypeAttr(s string) metadata.AttributeSqlserverInputType {
	switch s {
	case "LeftInput":
		return metadata.AttributeSqlserverInputTypeLeftInput
	case "RightInput":
		return metadata.AttributeSqlserverInputTypeRightInput
	case "Input":
		return metadata.AttributeSqlserverInputTypeInput
	default:
		return metadata.AttributeSqlserverInputTypeRoot
	}
}
