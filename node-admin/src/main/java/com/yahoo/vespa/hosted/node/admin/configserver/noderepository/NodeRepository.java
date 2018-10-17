// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.node.admin.configserver.noderepository;

import com.yahoo.config.provision.HostName;
import com.yahoo.vespa.hosted.provision.Node;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * @author stiankri
 */
public interface NodeRepository {

    void addNodes(List<AddNode> nodes);

    List<NodeSpec> getNodes(HostName baseHostName);

    default NodeSpec getNode(HostName hostName) {
        return getOptionalNode(hostName).orElseThrow(() -> new NoSuchNodeException(hostName + " not found in node-repo"));
    }

    Optional<NodeSpec> getOptionalNode(HostName hostName);

    Map<HostName, Acl> getAcls(HostName hostname);

    void updateNodeAttributes(HostName hostName, NodeAttributes nodeAttributes);

    void setNodeState(HostName hostName, Node.State nodeState);

    void scheduleReboot(HostName hostname);
}
