// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.node.admin.task.util.network;

import com.google.common.net.InetAddresses;
import com.yahoo.config.provision.HostName;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author smorgrav
 */
public class IPAddressesMock implements IPAddresses {

    private final Map<HostName, List<InetAddress>> otherAddresses = new HashMap<>();

    public IPAddressesMock addAddress(String hostname, String ip) {
        return addAddress(HostName.from(hostname), ip);
    }

    public IPAddressesMock addAddress(HostName hostname, String ip) {
        List<InetAddress> addresses = otherAddresses.getOrDefault(hostname, new ArrayList<>());
        addresses.add(InetAddresses.forString(ip));
        otherAddresses.put(hostname, addresses);
        return this;
    }

    @Override
    public InetAddress[] getAddresses(HostName hostname) {
        List<InetAddress> addresses = otherAddresses.get(hostname);
        if (addresses == null) return new InetAddress[0];
        return addresses.toArray(new InetAddress[addresses.size()]);
    }
}
