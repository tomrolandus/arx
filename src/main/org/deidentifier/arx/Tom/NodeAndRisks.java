package org.deidentifier.arx.Tom;

import org.deidentifier.arx.ARXLattice;

public class NodeAndRisks<node, prosecutorScore, journalistScore, marketerScore> {
    private ARXLattice.ARXNode node;
    private double[] risks;

    public NodeAndRisks(ARXLattice.ARXNode node, double[] risks){
        this.node = node;
        this.risks = risks;
    }

    public ARXLattice.ARXNode getNode() {
        return node;
    }

    public void setNode(ARXLattice.ARXNode node) {
        this.node = node;
    }

    public double[] getRisks() {
        return risks;
    }

    public void setRisks(double[] risks) {
        this.risks = risks;
    }
}
