package org.ow2.sirocco.cloudmanager.connector.scvmm;

import java.io.IOException;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.ow2.sirocco.cloudmanager.connector.api.ConnectorException;
import org.ow2.sirocco.cloudmanager.connector.api.ICloudProviderConnector;
import org.ow2.sirocco.cloudmanager.connector.api.IComputeService;
import org.ow2.sirocco.cloudmanager.connector.api.IImageService;
import org.ow2.sirocco.cloudmanager.connector.api.INetworkService;
import org.ow2.sirocco.cloudmanager.connector.api.ISystemService;
import org.ow2.sirocco.cloudmanager.connector.api.IVolumeService;
import org.ow2.sirocco.cloudmanager.connector.api.ProviderTarget;
import org.ow2.sirocco.cloudmanager.connector.api.ResourceNotFoundException;
import org.ow2.sirocco.cloudmanager.model.cimi.DiskTemplate;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroup;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroupCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroupNetwork;
import org.ow2.sirocco.cloudmanager.model.cimi.Machine;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineConfiguration;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineImage;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineTemplateNetworkInterface;
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
import org.ow2.sirocco.cloudmanager.model.cimi.extension.ProviderMapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.msopentech.odatajclient.engine.client.http.HttpClientFactory;
import com.msopentech.odatajclient.engine.client.http.HttpMethod;
import com.msopentech.odatajclient.engine.communication.request.UpdateType;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataCUDRequestFactory;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataEntityCreateRequest;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataEntityUpdateRequest;
import com.msopentech.odatajclient.engine.communication.request.retrieve.ODataEntityRequest;
import com.msopentech.odatajclient.engine.communication.request.retrieve.ODataEntitySetRequest;
import com.msopentech.odatajclient.engine.communication.request.retrieve.ODataRetrieveRequestFactory;
import com.msopentech.odatajclient.engine.communication.response.ODataEntityCreateResponse;
import com.msopentech.odatajclient.engine.communication.response.ODataEntityUpdateResponse;
import com.msopentech.odatajclient.engine.communication.response.ODataRetrieveResponse;
import com.msopentech.odatajclient.engine.data.ODataCollectionValue;
import com.msopentech.odatajclient.engine.data.ODataComplexValue;
import com.msopentech.odatajclient.engine.data.ODataEntity;
import com.msopentech.odatajclient.engine.data.ODataEntitySet;
import com.msopentech.odatajclient.engine.data.ODataFactory;
import com.msopentech.odatajclient.engine.data.ODataPrimitiveValue;
import com.msopentech.odatajclient.engine.data.metadata.edm.EdmSimpleType;
import com.msopentech.odatajclient.engine.format.ODataPubFormat;
import com.msopentech.odatajclient.engine.uri.ODataURIBuilder;
import com.msopentech.odatajclient.engine.utils.Configuration;

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

    
    /**
     * SCVMMProvider
     *
     */
    private static class SCVMMProvider {

        private CloudProviderAccount cloudProviderAccount;

        private CloudProviderLocation cloudProviderLocation;
        
        private String serviceRootURL;
        
        private String stampId;
        
        public SCVMMProvider(final CloudProviderAccount cloudProviderAccount,
        		final CloudProviderLocation cloudProviderLocation) {
        	this.cloudProviderAccount = cloudProviderAccount;
        	this.cloudProviderLocation = cloudProviderLocation;
        	this.serviceRootURL = cloudProviderAccount.getCloudProvider().getEndpoint();
        	Configuration.setHttpClientFactory(new SimpleHttpsClientFactory());
        }

        //
        // Compute Service
        //

        public List<MachineConfiguration> getMachineConfigs() {
        	logger.debug("Getting machine configs...");
        	
        	final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("HardwareProfiles");
		
			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
		
			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();
		
            List<MachineConfiguration> result = new ArrayList<>();
            for (ODataEntity entity : entitySet.getEntities()) {
            	MachineConfiguration machineConfig = new MachineConfiguration();
            	
            	// set name
            	machineConfig.setName(entity.getProperty("Name").getValue()
            			.toString());
            	
            	// set cpu
            	machineConfig.setCpu(entity.getProperty("CPUCount").getValue()
            			.asPrimitive().<Integer> toCastValue());
            	
            	// set memory
            	machineConfig.setMemory(entity.getProperty("Memory").getValue()
            			.asPrimitive().<Integer> toCastValue());
            	
            	// set disks
            	List<DiskTemplate> disks = new ArrayList<>();
                DiskTemplate disk = new DiskTemplate();
                if (entity.getProperty("TotalVHDCapacity").hasNullValue()) {
                	disk.setCapacity(0);
                } else {
                	disk.setCapacity(entity.getProperty("TotalVHDCapacity").getValue()
                			.asPrimitive().<Integer> toCastValue());
                }
                disks.add(disk);
                machineConfig.setDisks(disks);
                
            	// set provider mappings
            	ProviderMapping providerMapping = new ProviderMapping();
                providerMapping.setProviderAssignedId(
                		entity.getProperty("ID").getValue().toString());
                providerMapping.setProviderAccount(this.cloudProviderAccount);
                machineConfig.setProviderMappings(Collections.singletonList(providerMapping));
            	
            	result.add(machineConfig);
			}
        	
            return result;
        }

 
        /**
         * Creates a virtual machine with the configuration passed as a parameter
         * @param machineCreate - virtual machine configuration 
         * @return the virtual machine created
         * @throws ConnectorException
         */
        public Machine createMachine(final MachineCreate machineCreate) throws ConnectorException {
        	final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntitySetSegment("VirtualMachines");
		
			ODataEntity machineConfig = ODataFactory.newEntity("VMM.VirtualMachine");
			
			// get CloudId and set StampId
			String cloudId = getCloudIdFromName(
					cloudProviderAccount.getProperties().get("cloudName"));
		
			// add StampId
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid)
							.setValue(UUID.fromString(stampId)).build()));

			// add cloud id
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("CloudId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid)
							.setValue(UUID.fromString(cloudId)).build()));
						
			// add name
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText(machineCreate.getName())
							.setType(EdmSimpleType.String).build()));
		
			// add VMTemplateId
			ProviderMapping mapping = ProviderMapping.find(
					machineCreate.getMachineTemplate().getMachineImage(),
	                cloudProviderAccount, cloudProviderLocation);
            if (mapping == null) {
                throw new ConnectorException("Cannot find imageId for image "
                    + machineCreate.getMachineTemplate().getMachineImage().getName());
            }
            String templateId = mapping.getProviderAssignedId();
//			String templateId = machineCreate.getMachineTemplate()
//					.getMachineImage().getProviderAssignedId();
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("VMTemplateId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid)
							.setValue(UUID.fromString(templateId)).build()));
			
			// add NewVirtualNetworkAdapterInput
			ODataCollectionValue collection = new ODataCollectionValue(
					"Collection(VMM.NewVMVirtualNetworkAdapterInput)");

			if (machineCreate.getMachineTemplate().getNetworkInterfaces() != null) {
	            for (MachineTemplateNetworkInterface nic : 
	            		machineCreate.getMachineTemplate().getNetworkInterfaces()) {
	            	
	    			ODataComplexValue nicOData = 
	    					new ODataComplexValue("NewVMVirtualNetworkAdapterInput");
	    			
	    			nicOData.add(ODataFactory.newPrimitiveProperty("VMNetworkName",
	    					new ODataPrimitiveValue.Builder()
	    							.setText(getNetworkNameFromId(nic.getNetwork().getProviderAssignedId()))
	    							.setType(EdmSimpleType.String).build()));
	    			nicOData.add(ODataFactory.newPrimitiveProperty("IPv4AddressType", null));
	    			nicOData.add(ODataFactory.newPrimitiveProperty("IPv6AddressType", null));
	    			nicOData.add(ODataFactory.newPrimitiveProperty("MACAddress", null));
	    			nicOData.add(ODataFactory.newPrimitiveProperty("MACAddressType", null));
	    			nicOData.add(ODataFactory.newPrimitiveProperty("VLanEnabled", null));
	    			nicOData.add(ODataFactory.newPrimitiveProperty("VLanId", null));
	    			
	    			collection.add(nicOData);
	            }
	        }
			
			machineConfig.addProperty(ODataFactory.newCollectionProperty(
					"NewVirtualNetworkAdapterInput", collection));
			
			// add owner
			ODataComplexValue owner = new ODataComplexValue("VMM.UserAndRole");
			
			/// set user name
			owner.add(ODataFactory.newPrimitiveProperty("UserName",
					new ODataPrimitiveValue.Builder()
							.setText(cloudProviderAccount.getLogin())
							.setType(EdmSimpleType.String).build()));
			
			/// set role name
			String tenantName = cloudProviderAccount.getProperties().get("tenantName");
			owner.add(ODataFactory.newPrimitiveProperty("RoleName",
					new ODataPrimitiveValue.Builder().setText(tenantName)
							.setType(EdmSimpleType.String).build()));

			/// set role id
			owner.add(ODataFactory.newPrimitiveProperty("RoleID",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid)
							.setValue(UUID.fromString(
									tenantName.substring(tenantName.length()-36)))
							.build()));
			
			machineConfig.addProperty(ODataFactory.newComplexProperty("Owner", owner));
			
			// create and execute request			
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), machineConfig);
			createReq.setFormat(ODataPubFormat.ATOM);
			
			final ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				logger.error("Machine creation failed: " + createRes.getStatusMessage());
				throw new ConnectorException(
						"Machine creation failed: " + createRes.getStatusMessage());
			}

			machineConfig = createRes.getBody();
			
			logger.info("Machine creation succeed (ID=" + machineConfig
					.getProperty("ID").getValue() + ")");
			
			final Machine machine = new Machine();
			machine.setProviderAssignedId(
            		machineConfig.getProperty("ID").getValue().toString());
			
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
        
        
        //
        // OData functions
        //
        
        /**
         * Retrieves cloud identifier with its name and sets attribute StampId if not already set
         * @param cloudName - cloud identified name
         * @return cloud identifier depending on the cloud name passed as a parameter
         */
        private String getCloudIdFromName(String cloudName) {
        	final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("Clouds");
		
			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
		
			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entities = res.getBody();
			
			for (ODataEntity entity : entities.getEntities()) {
				if (entity.getProperty("Name").getValue().toString().equals(cloudName)) {
					// set StampId
					setStampId(entity.getProperty("StampId").getValue().toString());
					
					return entity.getProperty("ID").getValue().toString();
				}
			}
			
			return null;
        }
        
        /**
         * Retrieves network name with its identifier and sets attribute StampId if not already set
         * @param networkId - network identifier
         * @return network name depending on the network identifier passed as a parameter
         */
        private String getNetworkNameFromId(String networkId) {
        	final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMNetworks");
		
			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
		
			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entities = res.getBody();
			
			for (ODataEntity entity : entities.getEntities()) {
				if (entity.getProperty("ID").getValue().toString().equals(networkId)) {
					// set StampId
					setStampId(entity.getProperty("StampId").getValue().toString());
					
					return entity.getProperty("Name").getValue().toString();
				}
			}
			
			return null;
        }

        private void setStampId(String stampId) {
        	if (this.stampId == null)
        		this.stampId = stampId;
		}
        
        private Machine fromODataEntityToMachine(ODataEntity machine) {
        	Machine machineRes = new Machine();
        	machineRes.setProviderAssignedId(
            		machine.getProperty("ID").getValue().toString());
            machineRes.setName(
            		machine.getProperty("Name").getValue().toString());
            machineRes.setState(fromODataStatusToMachineState(
            		machine.getProperty("Status").getValue().toString()));
        	
        	return machineRes;
        }
        
        private Machine.State fromODataStatusToMachineState(String status) {
        	//TODO add others states
        	if (status.equals("Running")) {
				return Machine.State.STARTED;
				
			} else if (status.equals("PowerOff")) {
				return Machine.State.STOPPED;
				
			} else if (status.equals("UnderCreation")) {
        		return Machine.State.CREATING;
        		
			} else if (status.equals("Starting")) {
				return Machine.State.STARTING;
				
        	} else if (status.equals("Paused")) {
				return Machine.State.PAUSED;
				
			} else if (status.equals("Saved")) {
				return Machine.State.SUSPENDED;
				
			} else {
        		return Machine.State.ERROR;
        	}
        }
    
    
        /**
         * SimpleHttpsClientFactory
         *
         */
        private class SimpleHttpsClientFactory implements HttpClientFactory {

    		public HttpClient createHttpClient(final HttpMethod method,
    				final URI uri) {

    			SSLContext sslContext = null;
    			try {
    				sslContext = SSLContext.getInstance("SSL");

    				sslContext.init(null,
    						new TrustManager[] { new X509TrustManager() {
    							public X509Certificate[] getAcceptedIssuers() {
    								return new X509Certificate[] {};
    							}

    							public void checkClientTrusted(
    									X509Certificate[] certs, String authType) {
    							}

    							public void checkServerTrusted(
    									X509Certificate[] certs, String authType) {
    							}
    						} }, new SecureRandom());

    				SSLSocketFactory sf = new SSLSocketFactory(sslContext,
    						SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

    				Scheme httpsScheme = new Scheme("https", 443, sf);
    				SchemeRegistry schemeRegistry = new SchemeRegistry();
    				schemeRegistry.register(httpsScheme);

    				BasicClientConnectionManager cm = new BasicClientConnectionManager(
    						schemeRegistry);

    				DefaultHttpClient httpclient = new DefaultHttpClient(cm);

    				httpclient.getCredentialsProvider().setCredentials(
    						AuthScope.ANY,
    						new UsernamePasswordCredentials(
    								cloudProviderAccount.getLogin(),
    								cloudProviderAccount.getPassword()));
    				httpclient.addRequestInterceptor(
    						new PreemptiveAuthInterceptor(), 0);
    				return httpclient;

    			} catch (Exception e) {
    				e.printStackTrace();
    				return null;
    			}

    		}
    	}
        
        
        /**
         * PreemptiveAuthInterceptor
         *
         */
        private static class PreemptiveAuthInterceptor implements HttpRequestInterceptor {

    		@SuppressWarnings("deprecation")
    		public void process(final HttpRequest request, final HttpContext context)
    				throws HttpException, IOException {
    			AuthState authState = (AuthState) context
    					.getAttribute(ClientContext.TARGET_AUTH_STATE);

    			// If no auth scheme availalble yet, try to initialize it
    			// preemptively
    			if (authState.getAuthScheme() == null) {
    				CredentialsProvider credsProvider = (CredentialsProvider) context
    						.getAttribute(ClientContext.CREDS_PROVIDER);
    				HttpHost targetHost = (HttpHost) context
    						.getAttribute(ExecutionContext.HTTP_TARGET_HOST);
    				Credentials creds = credsProvider.getCredentials(new AuthScope(
    						targetHost.getHostName(), targetHost.getPort()));
    				if (creds == null)
    					throw new HttpException(
    							"No credentials for preemptive authentication");
    				authState.setAuthScheme(new BasicScheme());
    				authState.setCredentials(creds);
    			}

    		}

    	}
        
    }
    
}
