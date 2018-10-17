// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.node.admin.integrationTests;

import com.yahoo.config.provision.HostName;
import com.yahoo.vespa.hosted.node.admin.configserver.noderepository.NodeSpec;
import com.yahoo.vespa.hosted.node.admin.configserver.noderepository.AddNode;
import com.yahoo.vespa.hosted.node.admin.configserver.noderepository.NodeRepository;
import com.yahoo.vespa.hosted.node.admin.configserver.noderepository.NodeAttributes;
import com.yahoo.vespa.hosted.node.admin.configserver.noderepository.Acl;
import com.yahoo.vespa.hosted.provision.Node;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Mock with some simple logic
 *
 * @author dybis
 */
public class NodeRepoMock implements NodeRepository {
    private static final Object monitor = new Object();

    private final Map<HostName, NodeSpec> nodeRepositoryNodesByHostname = new HashMap<>();
    private final Map<HostName, Acl> acls = new HashMap<>();

    private final CallOrderVerifier callOrderVerifier;

    public NodeRepoMock(CallOrderVerifier callOrderVerifier) {
        this.callOrderVerifier = callOrderVerifier;
    }

    @Override
    public void addNodes(List<AddNode> nodes) { }

    @Override
    public List<NodeSpec> getNodes(HostName baseHostName) {
        synchronized (monitor) {
            return nodeRepositoryNodesByHostname.values().stream()
                    .filter(node -> baseHostName.equals(node.getParentHostname().orElse(null)))
                    .collect(Collectors.toList());
        }
    }

    @Override
    public Optional<NodeSpec> getOptionalNode(HostName hostName) {
        synchronized (monitor) {
            return Optional.ofNullable(nodeRepositoryNodesByHostname.get(hostName));
        }
    }

    @Override
    public Map<HostName, Acl> getAcls(HostName hostname) {
        synchronized (monitor) {
            return acls;
        }
    }

    @Override
    public void updateNodeAttributes(HostName hostName, NodeAttributes nodeAttributes) {
        synchronized (monitor) {
            callOrderVerifier.add("updateNodeAttributes with HostName: " + hostName + ", " + nodeAttributes);
        }
    }

    @Override
    public void setNodeState(HostName hostName, Node.State nodeState) {
        synchronized (monitor) {
            updateNodeRepositoryNode(new NodeSpec.Builder(getNode(hostName))
                    .state(nodeState)
                    .build());
            callOrderVerifier.add("setNodeState " + hostName + " to " + nodeState);
        }
    }

    @Override
    public void scheduleReboot(HostName hostname) {

    }

    public void updateNodeRepositoryNode(NodeSpec nodeSpec) {
        nodeRepositoryNodesByHostname.put(nodeSpec.getHostname(), nodeSpec);
    }

    public int getNumberOfContainerSpecs() {
        synchronized (monitor) {
            return nodeRepositoryNodesByHostname.size();
        }
    }
}
