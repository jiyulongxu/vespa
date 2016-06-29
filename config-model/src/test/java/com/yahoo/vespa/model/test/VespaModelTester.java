// Copyright 2016 Yahoo Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.model.test;

import com.yahoo.config.application.api.ApplicationPackage;
import com.yahoo.config.model.ConfigModelRegistry;
import com.yahoo.config.model.NullConfigModelRegistry;
import com.yahoo.config.model.deploy.DeployProperties;
import com.yahoo.config.model.deploy.DeployState;
import com.yahoo.config.model.provision.Host;
import com.yahoo.config.model.provision.Hosts;
import com.yahoo.config.model.provision.InMemoryProvisioner;
import com.yahoo.vespa.model.VespaModel;
import com.yahoo.vespa.model.test.utils.ApplicationPackageUtils;
import com.yahoo.vespa.model.test.utils.VespaModelCreatorWithMockPkg;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Helper class which sets up a system with multiple hosts.
 * Usage:
 * <code>
 *     VespaModelteser teser = new VespaModelTester();
 *     tester.addHosts(count, flavor);
 *     ... add more nodes
 *     VesoaModel model = tester.createModel(servicesString);
 *     ... assert on model
 * </code>
 * 
 * @author bratseth
 */
public class VespaModelTester {

    private final ConfigModelRegistry configModelRegistry;
    private Map<String, Collection<Host>> hosts = new HashMap<>();

    public VespaModelTester() {
        this(new NullConfigModelRegistry());
    }
    
    public VespaModelTester(ConfigModelRegistry configModelRegistry) {
        this.configModelRegistry = configModelRegistry;
    }
    
    /** Adds some hosts of the 'default' flavor to this system */
    public Hosts addHosts(int count) { return addHosts("default", count); }
    /** Adds some hosts to this system */
    public Hosts addHosts(String flavor, int count) { 
        Hosts hosts = new Hosts();
        for (int i = 0; i < count; i++)
            hosts.addHost(new com.yahoo.config.model.provision.Host(flavor + i), Collections.emptyList());
        this.hosts.put(flavor.isEmpty() ? "default" : flavor, hosts.getHosts());
        return hosts;
    }

    /** Creates a model which uses 0 as start index and fails on out of capacity */
    public VespaModel createModel(String services, String ... retiredHostNames) {
        return createModel(services, true, retiredHostNames);
    }
    /** Creates a model which uses 0 as start index */
    public VespaModel createModel(String services, boolean failOnOutOfCapacity, String ... retiredHostNames) {
        return createModel(services, failOnOutOfCapacity, 0, retiredHostNames);
    }
    /**
     * Creates a model using the hosts already added to this
     *
     * @param services the services xml string
     * @param failOnOutOfCapacity whether we should get an exception when not enough hosts of the requested flavor
     *        is available or if we should just silently receive a smaller allocation
     * @return the resulting model
     */
    public VespaModel createModel(String services, boolean failOnOutOfCapacity, int startIndexForClusters, String ... retiredHostNames) {
        VespaModelCreatorWithMockPkg modelCreatorWithMockPkg = new VespaModelCreatorWithMockPkg(null, services, ApplicationPackageUtils.generateSearchDefinition("type1"));
        ApplicationPackage appPkg = modelCreatorWithMockPkg.appPkg;
        DeployState deployState = new DeployState.Builder()
                .applicationPackage(appPkg)
                .modelHostProvisioner(new InMemoryProvisioner(hosts, failOnOutOfCapacity, startIndexForClusters, retiredHostNames))
                .properties((new DeployProperties.Builder()).hostedVespa(true).build()).build();
        return modelCreatorWithMockPkg.create(false, deployState, configModelRegistry);
    }

}
