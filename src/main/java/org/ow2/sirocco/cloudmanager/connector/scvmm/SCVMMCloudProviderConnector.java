package org.ow2.sirocco.cloudmanager.connector.scvmm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.ow2.sirocco.cloudmanager.connector.api.ConnectorException;
import org.ow2.sirocco.cloudmanager.connector.api.ICloudProviderConnector;
import org.ow2.sirocco.cloudmanager.connector.api.IComputeService;
import org.ow2.sirocco.cloudmanager.connector.api.IImageService;
import org.ow2.sirocco.cloudmanager.connector.api.INetworkService;
import org.ow2.sirocco.cloudmanager.connector.api.ISystemService;
import org.ow2.sirocco.cloudmanager.connector.api.IVolumeService;
import org.ow2.sirocco.cloudmanager.connector.api.ProviderTarget;
import org.ow2.sirocco.cloudmanager.connector.api.ResourceNotFoundException;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroup;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroupCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroupNetwork;
import org.ow2.sirocco.cloudmanager.model.cimi.Machine;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineConfiguration;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineImage;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineVolume;
import org.ow2.sirocco.cloudmanager.model.cimi.Network;
import org.ow2.sirocco.cloudmanager.model.cimi.NetworkCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.NetworkPort;
import org.ow2.sirocco.cloudmanager.model.cimi.NetworkPortCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.Volume;
import org.ow2.sirocco.cloudmanager.model.cimi.Volume.State;
import org.ow2.sirocco.cloudmanager.model.cimi.VolumeCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.VolumeImage;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.CloudProviderAccount;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.CloudProviderLocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SCVMMCloudProviderConnector implements ICloudProviderConnector, IComputeService, IVolumeService,
    INetworkService, IImageService {
    private static Logger logger = LoggerFactory.getLogger(SCVMMCloudProviderConnector.class);

    private List<SCVMMProvider> providers = new ArrayList<SCVMMProvider>();

    private synchronized SCVMMProvider getProvider(final ProviderTarget target) {
        for (SCVMMProvider provider : this.providers) {
            if (provider.cloudProviderAccount.getId().equals(target.getAccount().getId())) {
                // location can be null?
                if (provider.cloudProviderLocation != target.getLocation()) {
                    if (target.getLocation() != null) {
                        if (provider.cloudProviderLocation.getId().equals(target.getLocation().getId())) {
                            return provider;
                        }
                    }
                } else {
                    return provider;
                }
            }
        }

        SCVMMProvider provider = new SCVMMProvider(target.getAccount(), target.getLocation());
        this.providers.add(provider);
        return provider;
    }

    @Override
    public Set<CloudProviderLocation> getLocations() {
        return Collections.emptySet();
    }

    @Override
    public IComputeService getComputeService() throws ConnectorException {
        return this;
    }

    @Override
    public ISystemService getSystemService() throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public IVolumeService getVolumeService() throws ConnectorException {
        return this;
    }

    @Override
    public IImageService getImageService() throws ConnectorException {
        return this;
    }

    @Override
    public INetworkService getNetworkService() throws ConnectorException {
        return this;
    }

    @Override
    public Network createNetwork(final NetworkCreate networkCreate, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).createNetwork(networkCreate);
    }

    @Override
    public Network getNetwork(final String networkId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getNetwork(networkId);
    }

    @Override
    public Network.State getNetworkState(final String networkId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getNetworkState(networkId);
    }

    @Override
    public List<Network> getNetworks(final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getNetworks();
    }

    @Override
    public void deleteNetwork(final String networkId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).deleteNetwork(networkId);
    }

    @Override
    public void startNetwork(final String networkId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void stopNetwork(final String networkId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public NetworkPort createNetworkPort(final NetworkPortCreate networkPortCreate, final ProviderTarget target)
        throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public NetworkPort getNetworkPort(final String networkPortId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void deleteNetworkPort(final String networkPortId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void startNetworkPort(final String networkPortId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void stopNetworkPort(final String networkPortId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public ForwardingGroup createForwardingGroup(final ForwardingGroupCreate forwardingGroupCreate, final ProviderTarget target)
        throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public ForwardingGroup getForwardingGroup(final String forwardingGroupId, final ProviderTarget target)
        throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void deleteForwardingGroup(final String forwardingGroupId, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void addNetworkToForwardingGroup(final String forwardingGroupId, final ForwardingGroupNetwork fgNetwork,
        final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public void removeNetworkFromForwardingGroup(final String forwardingGroupId, final String networkId,
        final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public Volume createVolume(final VolumeCreate volumeCreate, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).createVolume(volumeCreate);
    }

    @Override
    public void deleteVolume(final String volumeId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).deleteVolume(volumeId);
    }

    @Override
    public Volume.State getVolumeState(final String volumeId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getVolumeState(volumeId);
    }

    @Override
    public Volume getVolume(final String volumeId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getVolume(volumeId);
    }

    @Override
    public VolumeImage createVolumeImage(final VolumeImage volumeImage, final ProviderTarget target) throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public VolumeImage createVolumeSnapshot(final String volumeId, final VolumeImage volumeImage, final ProviderTarget target)
        throws ConnectorException {
        throw new ConnectorException("unsupported operation");
    }

    @Override
    public VolumeImage getVolumeImage(final String volumeImageId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getVolumeImage(volumeImageId);
    }

    @Override
    public void deleteVolumeImage(final String volumeImageId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).deleteVolumeImage(volumeImageId);
    }

    @Override
    public Machine createMachine(final MachineCreate machineCreate, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).createMachine(machineCreate);
    }

    @Override
    public void startMachine(final String machineId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).startMachine(machineId);
    }

    @Override
    public void stopMachine(final String machineId, final boolean force, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).stopMachine(machineId, force);
    }

    @Override
    public void suspendMachine(final String machineId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).suspendMachine(machineId);
    }

    @Override
    public void restartMachine(final String machineId, final boolean force, final ProviderTarget target)
        throws ConnectorException {
        this.getProvider(target).restartMachine(machineId, force);
    }

    @Override
    public void pauseMachine(final String machineId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).pauseMachine(machineId);
    }

    @Override
    public void deleteMachine(final String machineId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).deleteMachine(machineId);
    }

    @Override
    public MachineImage captureMachine(final String machineId, final MachineImage machineImage, final ProviderTarget target)
        throws ConnectorException {
        return this.getProvider(target).captureMachine(machineId, machineImage);
    }

    @Override
    public Machine.State getMachineState(final String machineId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getMachineState(machineId);
    }

    @Override
    public Machine getMachine(final String machineId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getMachine(machineId);
    }

    @Override
    public void addVolumeToMachine(final String machineId, final MachineVolume machineVolume, final ProviderTarget target)
        throws ConnectorException {
        this.getProvider(target).addVolumeToMachine(machineId, machineVolume);
    }

    @Override
    public void removeVolumeFromMachine(final String machineId, final MachineVolume machineVolume, final ProviderTarget target)
        throws ConnectorException {
        this.getProvider(target).removeVolumeFromMachine(machineId, machineVolume);
    }

    @Override
    public void deleteMachineImage(final String imageId, final ProviderTarget target) throws ConnectorException {
        this.getProvider(target).deleteMachineImage(imageId);
    }

    @Override
    public MachineImage getMachineImage(final String machineImageId, final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getMachineImage(machineImageId);
    }

    @Override
    public List<MachineConfiguration> getMachineConfigs(final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getMachineConfigs();
    }

    @Override
    public List<MachineImage> getMachineImages(final boolean returnPublicImages, final Map<String, String> searchCriteria,
        final ProviderTarget target) throws ConnectorException {
        return this.getProvider(target).getMachineImages(returnPublicImages, searchCriteria);
    }

    private static class SCVMMProvider {

        private CloudProviderAccount cloudProviderAccount;

        private CloudProviderLocation cloudProviderLocation;

        public SCVMMProvider(final CloudProviderAccount cloudProviderAccount,
            final CloudProviderLocation cloudProviderLocation) {
        }

        //
        // Compute Service
        //

        public List<MachineConfiguration> getMachineConfigs() {
            // TODO
            List<MachineConfiguration> result = new ArrayList<>();
            return result;
        }

        public Machine createMachine(final MachineCreate machineCreate) throws ConnectorException {
            // TODO
            final Machine machine = new Machine();

            return machine;
        }

        public void startMachine(final String machineId) throws ConnectorException {
        }

        public void stopMachine(final String machineId, final boolean force) throws ConnectorException {
        }

        public void suspendMachine(final String machineId) throws ConnectorException {
            throw new ConnectorException("unsupported operation");
        }

        public void restartMachine(final String machineId, final boolean force) throws ConnectorException {
        }

        public void pauseMachine(final String machineId) throws ConnectorException {
            throw new ConnectorException("unsupported operation");
        }

        public MachineImage captureMachine(final String machineId, final MachineImage machineImage) throws ConnectorException {
            throw new ConnectorException("unsupported operation");
        }

        public void deleteMachine(final String machineId) throws ConnectorException {
        }

        public org.ow2.sirocco.cloudmanager.model.cimi.Machine.State getMachineState(final String machineId)
            throws ConnectorException {
            // TODO
            throw new ConnectorException("unsupported operation");
        }

        public Machine getMachine(final String machineId) throws ConnectorException {
            throw new ResourceNotFoundException("Machine with id " + machineId + " does not exist");
        }

        public void addVolumeToMachine(final String machineId, final MachineVolume machineVolume) throws ConnectorException {
        }

        public void removeVolumeFromMachine(final String machineId, final MachineVolume machineVolume) {
        }

        //
        // Volume Service
        //

        public Volume createVolume(final VolumeCreate volumeCreate) throws ConnectorException {
            // TODO
            throw new ConnectorException("unsupported operation");
        }

        public void deleteVolume(final String volumeId) throws ConnectorException {
        }

        public State getVolumeState(final String volumeId) throws ConnectorException {
            // TODO
            throw new ConnectorException("unsupported operation");
        }

        public Volume getVolume(final String volumeId) throws ConnectorException {
            throw new ConnectorException("unsupported operation");
        }

        public VolumeImage getVolumeImage(final String volumeImageId) throws ConnectorException {
            throw new ConnectorException("unsupported operation");
        }

        public void deleteVolumeImage(final String volumeImageId) throws ConnectorException {
            throw new ConnectorException("unsupported operation");
        }

        //
        // Image Service
        //

        public List<MachineImage> getMachineImages(final boolean returnAccountImagesOnly,
            final Map<String, String> searchCriteria) throws ConnectorException {
            List<MachineImage> result = new ArrayList<>();
            return result;
        }

        public void deleteMachineImage(final String imageId) {
            // TODO Auto-generated method stub

        }

        public MachineImage getMachineImage(final String machineImageId) {
            // TODO Auto-generated method stub
            return null;
        }

        //
        // Network Service
        //

        public void deleteNetwork(final String networkId) {
            // TODO Auto-generated method stub

        }

        public org.ow2.sirocco.cloudmanager.model.cimi.Network.State getNetworkState(final String networkId) {
            // TODO Auto-generated method stub
            return null;
        }

        public Network getNetwork(final String networkId) {
            // TODO Auto-generated method stub
            return null;
        }

        public Network createNetwork(final NetworkCreate networkCreate) {
            // TODO Auto-generated method stub
            return null;
        }

        public List<Network> getNetworks() {
            // TODO Auto-generated method stub
            return Collections.emptyList();
        }
    }

}
