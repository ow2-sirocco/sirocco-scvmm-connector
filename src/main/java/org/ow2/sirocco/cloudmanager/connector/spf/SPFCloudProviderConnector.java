package org.ow2.sirocco.cloudmanager.connector.spf;

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
import org.ow2.sirocco.cloudmanager.connector.api.BadStateException;
import org.ow2.sirocco.cloudmanager.connector.api.ConnectorException;
import org.ow2.sirocco.cloudmanager.connector.api.ICloudProviderConnector;
import org.ow2.sirocco.cloudmanager.connector.api.IComputeService;
import org.ow2.sirocco.cloudmanager.connector.api.IImageService;
import org.ow2.sirocco.cloudmanager.connector.api.INetworkService;
import org.ow2.sirocco.cloudmanager.connector.api.ISystemService;
import org.ow2.sirocco.cloudmanager.connector.api.IVolumeService;
import org.ow2.sirocco.cloudmanager.connector.api.ProviderTarget;
import org.ow2.sirocco.cloudmanager.connector.api.ResourceNotFoundException;
import org.ow2.sirocco.cloudmanager.model.cimi.Address;
import org.ow2.sirocco.cloudmanager.model.cimi.DiskTemplate;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroup;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroupCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.ForwardingGroupNetwork;
import org.ow2.sirocco.cloudmanager.model.cimi.Machine;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineConfiguration;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineDisk;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineImage;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineNetworkInterface;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineNetworkInterfaceAddress;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineTemplateNetworkInterface;
import org.ow2.sirocco.cloudmanager.model.cimi.MachineVolume;
import org.ow2.sirocco.cloudmanager.model.cimi.Network;
import org.ow2.sirocco.cloudmanager.model.cimi.NetworkCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.NetworkPort;
import org.ow2.sirocco.cloudmanager.model.cimi.NetworkPortCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.Subnet;
import org.ow2.sirocco.cloudmanager.model.cimi.Volume;
import org.ow2.sirocco.cloudmanager.model.cimi.Volume.State;
import org.ow2.sirocco.cloudmanager.model.cimi.VolumeCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.VolumeImage;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.CloudProviderAccount;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.CloudProviderLocation;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.ProviderMapping;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.SecurityGroup;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.SecurityGroupCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.SecurityGroupRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.msopentech.odatajclient.engine.client.http.HttpClientFactory;
import com.msopentech.odatajclient.engine.client.http.HttpMethod;
import com.msopentech.odatajclient.engine.communication.ODataClientErrorException;
import com.msopentech.odatajclient.engine.communication.ODataServerErrorException;
import com.msopentech.odatajclient.engine.communication.request.UpdateType;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataCUDRequestFactory;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataDeleteRequest;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataEntityCreateRequest;
import com.msopentech.odatajclient.engine.communication.request.cud.ODataEntityUpdateRequest;
import com.msopentech.odatajclient.engine.communication.request.retrieve.ODataEntityRequest;
import com.msopentech.odatajclient.engine.communication.request.retrieve.ODataEntitySetRequest;
import com.msopentech.odatajclient.engine.communication.request.retrieve.ODataRetrieveRequestFactory;
import com.msopentech.odatajclient.engine.communication.response.ODataDeleteResponse;
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

/**
 * Cloud provider connector for Microsoft Service Provider Foundation
 * 
 */
public class SPFCloudProviderConnector implements ICloudProviderConnector, IComputeService,
		IVolumeService, INetworkService, IImageService {
	private static Logger logger = LoggerFactory.getLogger(SPFCloudProviderConnector.class);

	private List<SPFProvider> providers = new ArrayList<SPFProvider>();

	private synchronized SPFProvider getProvider(final ProviderTarget target) {
		for (SPFProvider provider : this.providers) {
			if (provider.cloudProviderAccount.getId().equals(target.getAccount().getId())) {
				// location can be null?
				if (provider.cloudProviderLocation != target.getLocation()) {
					if (target.getLocation() != null) {
						if (provider.cloudProviderLocation.getId().equals(
								target.getLocation().getId())) {
							return provider;
						}
					}
				} else {
					return provider;
				}
			}
		}

		SPFProvider provider = new SPFProvider(target.getAccount(), target.getLocation());
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
	public Network createNetwork(final NetworkCreate networkCreate, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).createNetwork(networkCreate);
	}

	@Override
	public Network getNetwork(final String networkId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getNetwork(networkId);
	}

	@Override
	public Network.State getNetworkState(final String networkId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getNetworkState(networkId);
	}

	@Override
	public List<Network> getNetworks(final ProviderTarget target) throws ConnectorException {
		return this.getProvider(target).getNetworks();
	}

	@Override
	public void deleteNetwork(final String networkId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).deleteNetwork(networkId);
	}

	@Override
	public void startNetwork(final String networkId, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void stopNetwork(final String networkId, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public NetworkPort createNetworkPort(final NetworkPortCreate networkPortCreate,
			final ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public NetworkPort getNetworkPort(final String networkPortId, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void deleteNetworkPort(final String networkPortId, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void startNetworkPort(final String networkPortId, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void stopNetworkPort(final String networkPortId, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public ForwardingGroup createForwardingGroup(final ForwardingGroupCreate forwardingGroupCreate,
			final ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public ForwardingGroup getForwardingGroup(final String forwardingGroupId,
			final ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void deleteForwardingGroup(ForwardingGroup arg0, ProviderTarget arg1)
			throws ResourceNotFoundException, ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void addNetworkToForwardingGroup(final String forwardingGroupId,
			final ForwardingGroupNetwork fgNetwork, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void removeNetworkFromForwardingGroup(final String forwardingGroupId,
			final String networkId, final ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void addAddressToMachine(String machineId, Address address, ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public String addRuleToSecurityGroup(String groupId, SecurityGroupRule rule,
			ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public Address allocateAddress(Map<String, String> properties, ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public String createSecurityGroup(SecurityGroupCreate create, ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void deleteAddress(Address address, ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void deleteRuleFromSecurityGroup(String groupId, SecurityGroupRule rule,
			ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void deleteSecurityGroup(String groupId, ProviderTarget target)
			throws ResourceNotFoundException, ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public List<Address> getAddresses(ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public SecurityGroup getSecurityGroup(String groupId, ProviderTarget target)
			throws ResourceNotFoundException, ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public List<SecurityGroup> getSecurityGroups(ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void removeAddressFromMachine(String machineId, Address address, ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public Volume createVolume(final VolumeCreate volumeCreate, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).createVolume(volumeCreate);
	}

	@Override
	public void deleteVolume(final String volumeId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).deleteVolume(volumeId);
	}

	@Override
	public Volume.State getVolumeState(final String volumeId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getVolumeState(volumeId);
	}

	@Override
	public Volume getVolume(final String volumeId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getVolume(volumeId);
	}

	@Override
	public VolumeImage createVolumeImage(final VolumeImage volumeImage, final ProviderTarget target)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public VolumeImage createVolumeSnapshot(final String volumeId, final VolumeImage volumeImage,
			final ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public VolumeImage getVolumeImage(final String volumeImageId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getVolumeImage(volumeImageId);
	}

	@Override
	public void deleteVolumeImage(final String volumeImageId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).deleteVolumeImage(volumeImageId);
	}

	@Override
	public Machine createMachine(final MachineCreate machineCreate, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).createMachine(machineCreate);
	}

	@Override
	public void startMachine(final String machineId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).startMachine(machineId);
	}

	@Override
	public void stopMachine(final String machineId, final boolean force, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).stopMachine(machineId, force);
	}

	@Override
	public void suspendMachine(final String machineId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).suspendMachine(machineId);
	}

	@Override
	public void restartMachine(final String machineId, final boolean force,
			final ProviderTarget target) throws ConnectorException {
		this.getProvider(target).restartMachine(machineId, force);
	}

	@Override
	public void pauseMachine(final String machineId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).pauseMachine(machineId);
	}

	@Override
	public void deleteMachine(final String machineId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).deleteMachine(machineId);
	}

	@Override
	public MachineImage captureMachine(final String machineId, final MachineImage machineImage,
			final ProviderTarget target) throws ConnectorException {
		return this.getProvider(target).captureMachine(machineId, machineImage);
	}

	@Override
	public Machine.State getMachineState(final String machineId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getMachineState(machineId);
	}

	@Override
	public Machine getMachine(final String machineId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getMachine(machineId);
	}

	@Override
	public void addVolumeToMachine(final String machineId, final MachineVolume machineVolume,
			final ProviderTarget target) throws ConnectorException {
		this.getProvider(target).addVolumeToMachine(machineId, machineVolume);
	}

	@Override
	public void removeVolumeFromMachine(final String machineId, final MachineVolume machineVolume,
			final ProviderTarget target) throws ConnectorException {
		this.getProvider(target).removeVolumeFromMachine(machineId, machineVolume);
	}

	@Override
	public void deleteMachineImage(final String imageId, final ProviderTarget target)
			throws ConnectorException {
		this.getProvider(target).deleteMachineImage(imageId);
	}

	@Override
	public MachineImage getMachineImage(final String machineImageId, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getMachineImage(machineImageId);
	}

	@Override
	public List<MachineConfiguration> getMachineConfigs(final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getMachineConfigs();
	}

	@Override
	public List<MachineImage> getMachineImages(final boolean returnPublicImages,
			final Map<String, String> searchCriteria, final ProviderTarget target)
			throws ConnectorException {
		return this.getProvider(target).getMachineImages(returnPublicImages, searchCriteria);
	}

	/**
	 * Provider for Microsoft Service Provider Foundation
	 * 
	 */
	private static class SPFProvider {

		public enum MachineAction {
			START("Start"),
			STOP("Stop"),
			SAVE_STATE("SaveState"),
			DISCARD_SAVED_STATE("DiscardSavedState"),
			SUSPEND("Suspend"),
			SHUTDOWN("Shutdown"),
			RESUME("Resume"),
			REPAIR("Repair"),
			REFRESH("Refresh"),
			RESET("Reset"),
			STORE("Store"),
			DEPLOY("Deploy");

			private String action;

			private MachineAction(String action) {
				this.action = action;
			}
		}

		private CloudProviderAccount cloudProviderAccount;

		private CloudProviderLocation cloudProviderLocation;

		private String serviceRootURL;

		private final String stampId;

		/**
		 * Initializes a SPF provider by instantiating a HTTP client connection with a HTTP request
		 * processing. It also queries the Stamp identifier
		 * @param cloudProviderAccount an account on a cloud provider
		 * @param cloudProviderLocation a geographical location where cloud resources are running
		 */
		public SPFProvider(final CloudProviderAccount cloudProviderAccount,
				final CloudProviderLocation cloudProviderLocation) {
			this.cloudProviderAccount = cloudProviderAccount;
			this.cloudProviderLocation = cloudProviderLocation;
			this.serviceRootURL = cloudProviderAccount.getCloudProvider().getEndpoint();
			Configuration.setHttpClientFactory(new SimpleHttpsClientFactory());
			stampId = getStampId();
			logger.info("StampId=" + stampId);
		}

		//
		// Compute Service
		//

		/**
		 * Returns all VMM hardware profiles
		 * @return a list of all machine configurations
		 */
		public List<MachineConfiguration> getMachineConfigs() {
			logger.info("Getting machine configs");

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
				machineConfig.setName(entity.getProperty("Name").getValue().toString());

				// set cpu
				machineConfig.setCpu(entity.getProperty("CPUCount").getValue().asPrimitive()
						.<Integer> toCastValue());

				// set memory
				machineConfig.setMemory(entity.getProperty("Memory").getValue().asPrimitive()
						.<Integer> toCastValue());

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
				providerMapping.setProviderAssignedId(entity.getProperty("ID").getValue()
						.toString());
				providerMapping.setProviderAccount(this.cloudProviderAccount);
				machineConfig.setProviderMappings(Collections.singletonList(providerMapping));

				result.add(machineConfig);
			}

			logger.info("Number of machine configs: " + result.size());

			return result;
		}

		/**
		 * Creates a virtual machine with the configuration passed as a parameter
		 * @param machineCreate virtual machine configuration
		 * @return the virtual machine created
		 * @throws ResourceNotFoundException if cannot find machine image
		 * @throws ConnectorException if machine creation failed
		 */
		public Machine createMachine(final MachineCreate machineCreate)
				throws ResourceNotFoundException, ConnectorException {
			logger.info("Creating machine (Name=" + machineCreate.getName() + ")");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntitySetSegment("VirtualMachines");

			ODataEntity machineConfig = ODataFactory.newEntity("VMM.VirtualMachine");

			// get CloudId
			String cloudId = getCloudIdFromName(cloudProviderAccount.getProperties().get(
					"cloudName"));

			// add StampId
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add cloud id
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("CloudId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(cloudId)).build()));

			// add name
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText(machineCreate.getName()).setType(
							EdmSimpleType.String).build()));

			// add VMTemplateId
			ProviderMapping mapping = ProviderMapping.find(machineCreate.getMachineTemplate()
					.getMachineImage(), cloudProviderAccount, cloudProviderLocation);
			if (mapping == null) {
				throw new ResourceNotFoundException("Cannot find imageId for image "
						+ machineCreate.getMachineTemplate().getMachineImage().getName());
			}
			String templateId = mapping.getProviderAssignedId();
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("VMTemplateId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(templateId)).build()));

			// add NewVirtualNetworkAdapterInput
			ODataCollectionValue collection = new ODataCollectionValue(
					"Collection(VMM.NewVMVirtualNetworkAdapterInput)");

			if (machineCreate.getMachineTemplate().getNetworkInterfaces() != null) {
				for (MachineTemplateNetworkInterface nic : machineCreate.getMachineTemplate()
						.getNetworkInterfaces()) {

					ODataComplexValue nicOData = new ODataComplexValue(
							"NewVMVirtualNetworkAdapterInput");

					nicOData.add(ODataFactory.newPrimitiveProperty("VMNetworkName",
							new ODataPrimitiveValue.Builder().setText(
									getNetworkNameFromId(nic.getNetwork().getProviderAssignedId()))
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

			// owner: set user name
			String userName = cloudProviderAccount.getProperties().get("tenantName");
			owner.add(ODataFactory.newPrimitiveProperty("UserName",
					new ODataPrimitiveValue.Builder().setText(userName).setType(
							EdmSimpleType.String).build()));

			// owner: set role name
			// String roleName = getRoleNameFromUserName(userName);
			String roleName = cloudProviderAccount.getProperties().get("tenantRoleName");
			owner.add(ODataFactory.newPrimitiveProperty("RoleName",
					new ODataPrimitiveValue.Builder().setText(roleName).setType(
							EdmSimpleType.String).build()));

			// owner: set role id
			// String roleID = roleName.substring(roleName.length() - 36);
			String roleID = cloudProviderAccount.getProperties().get("tenantID");
			owner.add(ODataFactory.newPrimitiveProperty("RoleID", new ODataPrimitiveValue.Builder()
					.setType(EdmSimpleType.Guid).setValue(UUID.fromString(roleID)).build()));

			machineConfig.addProperty(ODataFactory.newComplexProperty("Owner", owner));

			// add credential (user name)
			try {
				machineConfig.addProperty(ODataFactory.newPrimitiveProperty("LocalAdminUserName",
						new ODataPrimitiveValue.Builder().setText(
								machineCreate.getMachineTemplate().getCredential().getUserName())
								.setType(EdmSimpleType.String).build()));
			} catch (NullPointerException e) {
				// nothing to do
			}

			// add credential (password)
			try {
				machineConfig.addProperty(ODataFactory.newPrimitiveProperty("LocalAdminPassword",
						new ODataPrimitiveValue.Builder().setText(
								machineCreate.getMachineTemplate().getCredential().getPassword())
								.setType(EdmSimpleType.String).build()));
			} catch (NullPointerException e) {
				// nothing to do
			}

			// create and execute request
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), machineConfig);
			createReq.setFormat(ODataPubFormat.ATOM);

			final ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				throw new ConnectorException("Machine creation failed: "
						+ createRes.getStatusMessage());
			}

			machineConfig = createRes.getBody();

			logger.info("Machine creation succeed (" + "Name="
					+ machineConfig.getProperty("Name").getValue() + ", ID="
					+ machineConfig.getProperty("ID").getValue() + ")");

			final Machine machine = new Machine();
			machine.setProviderAssignedId(machineConfig.getProperty("ID").getValue().toString());

			return machine;
		}

		/**
		 * Starts a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @throws ConnectorException if starting the machine failed
		 */
		public void startMachine(final String machineId) throws ConnectorException {
			actionMachine(machineId, MachineAction.START);
		}

		/**
		 * Stops a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @throws ConnectorException if stopping the machine failed
		 */
		public void stopMachine(final String machineId, final boolean force)
				throws ConnectorException {
			actionMachine(machineId, MachineAction.STOP);
		}

		/**
		 * Suspends a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @throws ConnectorException if suspending the machine failed
		 */
		public void suspendMachine(final String machineId) throws ConnectorException {
			actionMachine(machineId, MachineAction.SUSPEND);
		}

		/**
		 * Restarts a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @throws ConnectorException if restarting the machine failed
		 */
		public void restartMachine(final String machineId, final boolean force)
				throws ConnectorException {
			actionMachine(machineId, MachineAction.RESET);
		}

		/**
		 * Pauses a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @throws ConnectorException if pausing the machine failed
		 */
		public void pauseMachine(final String machineId) throws ConnectorException {
			actionMachine(machineId, MachineAction.SUSPEND);
		}

		public MachineImage captureMachine(final String machineId, final MachineImage machineImage)
				throws ConnectorException {
			throw new ConnectorException("unsupported operation");
		}

		/**
		 * Deletes a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @throws ConnectorException if the machine deletion failed
		 */
		public void deleteMachine(final String machineId) throws ConnectorException {
			logger.info("Deleting machine (ID=" + machineId + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key);

			final ODataDeleteRequest req = ODataCUDRequestFactory.getDeleteRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			// Stop the VM if it is running
			if (!getMachineState(machineId).equals(Machine.State.STOPPED)) {
				stopMachine(machineId, true);
			}

			final ODataDeleteResponse res = req.execute();

			// response processing
			if (res.getStatusCode() != 204) {
				throw new ConnectorException("Machine deletion failed (HTTP status: "
						+ res.getStatusCode() + "):" + res.getStatusMessage());
			}

			logger.info("Machine deletion succeed with ID=" + machineId);
		}

		/**
		 * Returns the state of a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @return the machine state requested by its ID
		 * @throws ResourceNotFoundException if the requested machine does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		public Machine.State getMachineState(final String machineId)
				throws ResourceNotFoundException, ConnectorException {
			logger.info("Getting machine state (ID=" + machineId + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key).select(
							"Status");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();

				ODataEntity machine = res.getBody();
				String status = machine.getProperty("Status").getValue().toString();
				logger.info("Machine state: " + status + " (ID=" + machineId + ")");

				return fromODataVMStatusToMachineState(status);

			} catch (ODataClientErrorException e) {
				// catch exception in case of not founding machine
				if (e.getStatusLine().getStatusCode() == 404) {
					throw new ResourceNotFoundException("Machine with id " + machineId
							+ " does not exist");
				}
				throw new ConnectorException(e);
			}
		}

		/**
		 * Returns a machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @return the machine requested by its ID
		 * @throws ResourceNotFoundException if the requested machine does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		public Machine getMachine(final String machineId) throws ResourceNotFoundException,
				ConnectorException {
			logger.info("Getting machine (ID=" + machineId + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key);

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();

				ODataEntity machine = res.getBody();
				logger.info("Machine requested: " + "Name="
						+ machine.getProperty("Name").getValue() + ", " + "ID="
						+ machine.getProperty("ID").getValue());

				return fromODataVMToMachine(machine);

			} catch (ODataClientErrorException e) {
				// catch exception in case of not founding machine
				if (e.getStatusLine().getStatusCode() == 404) {
					throw new ResourceNotFoundException("Machine with id " + machineId
							+ " does not exist");
				}
				throw new ConnectorException(e);
			}
		}

		public void addVolumeToMachine(final String machineId, final MachineVolume machineVolume)
				throws ConnectorException {
		}

		public void removeVolumeFromMachine(final String machineId,
				final MachineVolume machineVolume) {
		}

		//
		// Volume Service
		//

		public Volume createVolume(final VolumeCreate volumeCreate) throws ConnectorException {
			throw new ConnectorException("unsupported operation");
		}

		public void deleteVolume(final String volumeId) throws ConnectorException {
		}

		public State getVolumeState(final String volumeId) throws ConnectorException {
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

		/*
		public List<MachineImage> getMachineImages(final boolean returnAccountImagesOnly,
				final Map<String, String> searchCriteria) throws ConnectorException {
			logger.info("Getting machine images");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualHardDisks").filter(
							"StampId eq guid'" + stampId + "'");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<MachineImage> result = new ArrayList<MachineImage>();

			for (ODataEntity vhd : entitySet.getEntities()) {
				MachineImage machineImage = new MachineImage();
				// set name
				machineImage.setName(vhd.getProperty("Name").getValue().toString());
				// TODO set state
				machineImage.setState(MachineImage.State.AVAILABLE);
				// TODO set type
				machineImage.setType(MachineImage.Type.IMAGE);
				// set provider mappings
				ProviderMapping providerMapping = new ProviderMapping();
				providerMapping.setProviderAssignedId(vhd.getProperty("ID").getValue().toString());
				providerMapping.setProviderAccount(cloudProviderAccount);
				providerMapping.setProviderLocation(cloudProviderLocation);
				machineImage.setProviderMappings(Collections.singletonList(providerMapping));
				// set image location
				machineImage.setImageLocation(vhd.getProperty("Location").getValue().toString());

				result.add(machineImage);
			}

			return result;
		}
		 */

		/**
		 * Returns all VMM virtual machine templates
		 * @param returnAccountImagesOnly never used
		 * @param searchCriteria never used
		 * @return a list of all virtual machine templates
		 */
		public List<MachineImage> getMachineImages(final boolean returnAccountImagesOnly,
				final Map<String, String> searchCriteria) {
			logger.info("Getting machine images");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMTemplates");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<MachineImage> result = new ArrayList<MachineImage>();
			for (ODataEntity template : entitySet.getEntities()) {
				MachineImage machineImage = new MachineImage();

				// set name
				machineImage.setName(template.getProperty("Name").getValue().toString());
				// set provider mappings
				ProviderMapping providerMapping = new ProviderMapping();
				providerMapping.setProviderAssignedId(template.getProperty("ID").getValue()
						.toString());
				providerMapping.setProviderAccount(cloudProviderAccount);
				providerMapping.setProviderLocation(cloudProviderLocation);
				machineImage.setProviderMappings(Collections.singletonList(providerMapping));

				result.add(machineImage);
			}

			logger.info("Number of machine images: " + result.size());

			return result;
		}

		public void deleteMachineImage(final String imageId) {
		}

		public MachineImage getMachineImage(final String machineImageId) {
			return null;
		}

		//
		// Network Service
		//

		public void deleteNetwork(final String networkId) {
		}

		public Network.State getNetworkState(final String networkId) {
			return null;
		}

		/**
		 * Returns a network defined by its ID
		 * @param networkId virtual network identifier
		 * @return the network requested by its ID
		 * @throws ResourceNotFoundException if the requested network does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		public Network getNetwork(final String networkId) throws ResourceNotFoundException,
				ConnectorException {
			logger.info("Getting network (ID=" + networkId + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(networkId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMNetworks").appendKeySegment(key);

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();

				ODataEntity network = res.getBody();
				logger.info("Network requested: " + "Name="
						+ network.getProperty("Name").getValue() + ", " + "ID="
						+ network.getProperty("ID").getValue());

				return fromODataNetworkToCimiNetwork(network);

			} catch (ODataClientErrorException e) {
				// catch exception in case of not founding network
				if (e.getStatusLine().getStatusCode() == 404) {
					throw new ResourceNotFoundException("Network with id " + networkId
							+ " does not exist");
				}
				throw new ConnectorException(e);
			}
		}

		/**
		 * Creates a virtual network with the configuration passed as a parameter
		 * @param networkCreate virtual network configuration
		 * @return the virtual network created
		 * @throws ConnectorException if network creation failed
		 */
		public Network createNetwork(final NetworkCreate networkCreate) throws ConnectorException {
			logger.info("Creating network (Name=" + networkCreate.getName() + ")");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntitySetSegment("VMNetworks");

			ODataEntity networkConfig = ODataFactory.newEntity("VMM.VMNetwork");

			// add stampId
			networkConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add Name
			networkConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText(networkCreate.getName()).build()));

			// add LogicalNetworkId
			networkConfig.addProperty(ODataFactory.newPrimitiveProperty("LogicalNetworkId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(getNetworkAllowingVirtualization())).build()));

			// create and execute request
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), networkConfig);
			createReq.setFormat(ODataPubFormat.ATOM);

			final ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				throw new ConnectorException("Network creation failed: "
						+ createRes.getStatusMessage());
			}

			networkConfig = createRes.getBody();

			logger.info("Network creation succeed (" + "Name="
					+ networkConfig.getProperty("Name").getValue() + ", ID="
					+ networkConfig.getProperty("ID").getValue() + ")");

			// add subnets
			for (Subnet subnet : networkCreate.getNetworkTemplate().getNetworkConfig().getSubnets()) {
				createSubnet(subnet, networkConfig.getProperty("ID").getValue().toString());
			}

			return fromODataNetworkToCimiNetwork(networkConfig);
		}

		/**
		 * Returns all VMM virtual networks
		 * @return a list of all existing virtual networks
		 */
		public List<Network> getNetworks() {
			logger.info("Getting networks");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMNetworks");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<Network> result = new ArrayList<>();
			for (ODataEntity entity : entitySet.getEntities()) {
				result.add(fromODataNetworkToCimiNetwork(entity));
			}

			logger.info("Number of networks: " + result.size());

			return result;
		}

		//
		// OData functions
		//

		/**
		 * Queries Stamp identifier depending on cloud name
		 * @return Stamp identifier, or null if cannot find StampId with the given cloud name
		 */
		private final String getStampId() {
			String cloudName = cloudProviderAccount.getProperties().get("cloudName");
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("Clouds").filter("Name eq '" + cloudName + "'")
					.select("StampId");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entities = res.getBody();

			if (entities.getEntities().isEmpty()) {
				logger.error("Cannot find StampId with the given cloud '" + cloudName + "'");
				return null;
			} else {
				return entities.getEntities().get(0).getProperties().get(0).getValue().toString();
			}
		}

		/**
		 * Retrieves cloud identifier with its name
		 * @param cloudName cloud identified name
		 * @return cloud identifier depending on the cloud name passed as a parameter
		 * @throws ResourceNotFoundException if the requested cloud does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		private String getCloudIdFromName(String cloudName) throws ResourceNotFoundException,
				ConnectorException {
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("Clouds").filter("Name eq '" + cloudName + "'")
					.select("ID");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntitySet> res = req.execute();

				return res.getBody().getEntities().get(0).getProperties().get(0).getValue()
						.toString();

			} catch (ODataClientErrorException e) {
				// catch exception in case of not founding cloud
				if (e.getStatusLine().getStatusCode() == 404) {
					throw new ResourceNotFoundException("Cloud '" + cloudName + "'does not exist");
				}
				throw new ConnectorException(e);
			}
		}

		/**
		 * Retrieves network name with its identifier
		 * @param networkId network identifier
		 * @return network name depending on the network identifier passed as a parameter
		 * @throws ResourceNotFoundException if the requested network does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		private String getNetworkNameFromId(String networkId) throws ResourceNotFoundException,
				ConnectorException {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(networkId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMNetworks").appendKeySegment(key).select("Name");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();

				return res.getBody().getProperties().get(0).getValue().toString();

			} catch (ODataClientErrorException e) {
				// catch exception in case of not founding network
				if (e.getStatusLine().getStatusCode() == 404) {
					throw new ResourceNotFoundException("Network does not exist with ID="
							+ networkId);
				}
				throw new ConnectorException(e);
			}
		}

		/**
		 * Retrieves user role name with its unique name. A user role is the concatenation of the
		 * user name and an identifier.
		 * @param userName user identified name
		 * @return user role name depending on the user name passed as a parameter
		 * @throws ResourceNotFoundException if the requested user does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		private String getRoleNameFromUserName(String userName) throws ResourceNotFoundException,
				ConnectorException {
			// user role maximum length is 64 characters and identifier
			// length is 36 characters so user name is truncated if its
			// length is over than 27 characters
			if (userName.length() > 27) {
				userName = userName.substring(0, 27);
			}

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("UserRoles").filter(
							"startswith(Name, '" + userName + "')").select("Name");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntitySet> res = req.execute();

				return res.getBody().getEntities().get(0).getProperties().get(0).getValue()
						.toString();

			} catch (ODataClientErrorException e) {
				// catch exception in case of not founding user
				if (e.getStatusLine().getStatusCode() == 404) {
					throw new ResourceNotFoundException("User '" + userName + "'does not exist");
				}
				throw new ConnectorException(e);
			}
		}

		/**
		 * Controls the virtual machine defined by its ID
		 * @param machineId virtual machine identifier
		 * @param machineAction action to operate
		 * @throws ConnectorException if machine action failed
		 */
		private void actionMachine(String machineId, MachineAction machineAction)
				throws ConnectorException {
			logger.info("Operating machine (action=" + machineAction.action + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key);

			ODataEntity machine = ODataFactory.newEntity("VMM.VirtualMachine");

			// add ID
			machine.addProperty(ODataFactory.newPrimitiveProperty("ID",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(machineId)).build()));

			// add stampId
			machine.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add operation
			machine.addProperty(ODataFactory.newPrimitiveProperty("Operation",
					new ODataPrimitiveValue.Builder().setText(machineAction.action).setType(
							EdmSimpleType.String).build()));

			final ODataEntityUpdateRequest req = ODataCUDRequestFactory.getEntityUpdateRequest(
					uriBuilder.build(), UpdateType.REPLACE, machine);
			req.setFormat(ODataPubFormat.ATOM);

			final ODataEntityUpdateResponse res = req.execute();

			if (res.getStatusCode() != 200 && res.getStatusCode() != 204) {
				throw new ConnectorException(machineAction.action
						+ " machine failed (HTTP status: " + res.getStatusCode() + "): "
						+ res.getStatusMessage());
			}

			logger.info(machineAction.action + " machine succeed");
		}

		/**
		 * Maps a virtual machine OData entity to a Machine object
		 * @param entity a 'VirtualMachine' OData entity
		 * @return a Machine object mapped from OData entity parameter, or null if the entity is not
		 *         a virtual machine entity
		 */
		private Machine fromODataVMToMachine(ODataEntity entity) {
			if (!entity.getName().equals("VMM.VirtualMachine")) {
				return null;
			}

			Machine machine = new Machine();
			String machineId = entity.getProperty("ID").getValue().toString();

			// set id
			machine.setProviderAssignedId(machineId);

			// set name
			machine.setName(entity.getProperty("Name").getValue().toString());

			// set state
			machine.setState(fromODataVMStatusToMachineState(entity.getProperty("Status")
					.getValue().toString()));

			// set cpu
			machine.setCpu(entity.getProperty("CPUCount").getValue().asPrimitive()
					.<Integer> toCastValue());

			// set memory
			machine.setCpu(entity.getProperty("Memory").getValue().asPrimitive()
					.<Integer> toCastValue());

			// set disks
			List<MachineDisk> machineDisks = new ArrayList<MachineDisk>();
			for (ODataEntity vhd : getVirtualHardDisks(machineId).getEntities()) {
				MachineDisk machineDisk = new MachineDisk();
				// set disk name
				machineDisk.setName(vhd.getProperty("Name").getValue().toString());
				// set disk capacity
				Long capacity = vhd.getProperty("MaximumSize").getValue().asPrimitive()
						.<Long> toCastValue() / 1024; // Byte to KB
				machineDisk.setCapacity(capacity.intValue());
				machineDisks.add(machineDisk);
			}
			machine.setDisks(machineDisks);

			// set nics
			boolean ipAddressesUnavailable = false;
			List<MachineNetworkInterface> nics = new ArrayList<MachineNetworkInterface>();
			for (ODataEntity odataNetwork : getVirtualNetworkAdapters(machineId).getEntities()) {
				MachineNetworkInterface nic = new MachineNetworkInterface();

				// set network
				nic.setNetwork(fromODataNetworkAdapterToCimiNetwork(odataNetwork));

				// set addresses
				try {
					nic.setAddresses(getIPAddresses(machineId, odataNetwork.getProperty(
							"IPv4AddressType").getValue().toString(), odataNetwork.getProperty(
							"IPv6AddressType").getValue().toString()));
				} catch (BadStateException e) {
					logger.warn(e.getMessage());
					nic.setAddresses(new ArrayList<MachineNetworkInterfaceAddress>());
				}

				// update boolean used after to update machine state
				if (nic.getAddresses().isEmpty()) {
					ipAddressesUnavailable = true;
					continue;
				}

				// TODO set state
				nic.setState(MachineNetworkInterface.InterfaceState.ACTIVE);

				nics.add(nic);
			}
			machine.setNetworkInterfaces(nics);

			// if machine state is STARTED but its IP addresses are not yet available, then its
			// state is set to STARTING
			if (machine.getState().equals(Machine.State.STARTED) && ipAddressesUnavailable) {
				machine.setState(Machine.State.STARTING);
			}

			return machine;
		}

		/**
		 * Maps a virtual network adapter OData entity to a network Sirocco object
		 * @param odataNetworkAdapter a 'VirtualNetworkAdapter' OData entity
		 * @return a Network object mapped from OData entity parameter
		 */
		private Network fromODataNetworkAdapterToCimiNetwork(ODataEntity odataNetworkAdapter) {
			Network cimiNetwork = new Network();

			// set network name
			cimiNetwork.setName(odataNetworkAdapter.getProperty("VMNetworkName").getValue()
					.toString());

			// set network id
			cimiNetwork.setProviderAssignedId(odataNetworkAdapter.getProperty("VMNetworkId")
					.getValue().toString());

			// TODO set network state
			cimiNetwork.setState(Network.State.STARTED);

			// set network type
			if (odataNetworkAdapter.getProperty("Accessibility").getValue().toString().equals(
					"Public")) {
				cimiNetwork.setNetworkType(Network.Type.PUBLIC);
			} else {
				cimiNetwork.setNetworkType(Network.Type.PRIVATE);
			}

			// set network subnets
			cimiNetwork.setSubnets(getSubnets(cimiNetwork.getProviderAssignedId()));

			return cimiNetwork;
		}

		/**
		 * Maps a virtual network OData entity to a network Sirocco object
		 * @param odataNetwork a 'VMNetwork' OData entity
		 * @return a Network object mapped from OData entity parameter
		 */
		private Network fromODataNetworkToCimiNetwork(ODataEntity odataNetwork) {
			Network cimiNetwork = new Network();
			// set network name
			cimiNetwork.setName(odataNetwork.getProperty("Name").getValue().toString());
			// set network id
			cimiNetwork.setProviderAssignedId(odataNetwork.getProperty("ID").getValue().toString());
			// TODO set network state
			cimiNetwork.setState(Network.State.STARTED);
			// TODO set network type
			cimiNetwork.setNetworkType(Network.Type.PUBLIC);
			// set network subnets
			cimiNetwork.setSubnets(getSubnets(cimiNetwork.getProviderAssignedId()));

			return cimiNetwork;
		}

		/**
		 * Maps a virtual machine OData status to a Machine state
		 * @param status a virtual machine OData status
		 * @return a Machine state mapped from OData status parameter,
		 */
		private Machine.State fromODataVMStatusToMachineState(String status) {
			if (status.equals("UnderCreation")) {
				return Machine.State.CREATING;

			} else if (status.equals("Starting")) {
				return Machine.State.STARTING;

			} else if (status.equals("Running")) {
				return Machine.State.STARTED;

			} else if (status.equals("PoweringOff")) {
				return Machine.State.STOPPING;

			} else if (status.equals("PowerOff")) {
				return Machine.State.STOPPED;

			} else if (status.equals("Pausing")) {
				return Machine.State.PAUSING;

			} else if (status.equals("Paused")) {
				return Machine.State.PAUSED;

			} else if (status.equals("Saving")) {
				// XXX not sure
				return Machine.State.SUSPENDING;

			} else if (status.equals("Saved")) {
				// XXX not sure
				return Machine.State.SUSPENDED;

			} else if (status.equals("Deleting")) {
				return Machine.State.DELETING;

			} else if (status.equals("Restoring")) {
				// XXX not sure
				// Restoring is when a VM passed from saved state
				// to running state
				return Machine.State.STARTING;

			} else {
				logger.error("Unknown VM status: " + status);
				return Machine.State.ERROR;
			}
		}

		/**
		 * Retrieves virtual hard disks of a VM depending on its identifier passed as a parameter
		 * @param machineId VM identifier
		 * @return a set of virtual hard disks of the defined VM
		 */
		private ODataEntitySet getVirtualHardDisks(String machineId) {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key)
					.appendEntityTypeSegment("VirtualHardDisks");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			return res.getBody();
		}

		/**
		 * Retrieves virtual network adapters of a VM depending on its identifier passed as a
		 * parameter
		 * @param machineId VM identifier
		 * @return a set of virtual network adapters of the defined VM
		 */
		private ODataEntitySet getVirtualNetworkAdapters(String machineId) {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key)
					.appendEntityTypeSegment("VirtualNetworkAdapters");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			return res.getBody();
		}

		/**
		 * Get IP addresses of a specific virtual machine defined by its identifier passed as
		 * parameter
		 * @param machineId virtual machine identifier
		 * @param ipv4AllocationType IPv4 address type: dynamic or static
		 * @param ipv6AllocationType IPv6 address type: dynamic or static
		 * @return a list of machine network interface IP addresses
		 * @throws BadStateException if the virtual machine is not running, essential to retrieve IP
		 *         addresses
		 */
		private List<MachineNetworkInterfaceAddress> getIPAddresses(String machineId,
				String ipv4AllocationType, String ipv6AllocationType) throws BadStateException {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("VMId", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("GuestInfos").appendKeySegment(key);

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();
				final ODataEntity entity = res.getBody();

				List<MachineNetworkInterfaceAddress> nicAddresses = new ArrayList<MachineNetworkInterfaceAddress>();
				// IPv4Addresses
				String[] ipv4Addresses = entity.getProperty("IPv4Addresses").getValue().toString()
						.split(";");
				for (String ipv4Address : ipv4Addresses) {
					MachineNetworkInterfaceAddress nicAddress = new MachineNetworkInterfaceAddress();
					Address address = new Address();
					address.setIp(ipv4Address);
					address.setProtocol("IPv4");
					address.setAllocation(ipv4AllocationType);
					nicAddress.setAddress(address);
					nicAddresses.add(nicAddress);
				}
				// IPv6Addresses
				String[] ipv6Addresses = entity.getProperty("IPv6Addresses").getValue().toString()
						.split(";");
				for (String ipv6Address : ipv6Addresses) {
					MachineNetworkInterfaceAddress nicAddress = new MachineNetworkInterfaceAddress();
					Address address = new Address();
					address.setIp(ipv6Address);
					address.setProtocol("IPv6");
					address.setAllocation(ipv6AllocationType);
					nicAddress.setAddress(address);
					nicAddresses.add(nicAddress);
				}

				return nicAddresses;
			} catch (ODataServerErrorException e) {
				throw new BadStateException("The virtual machine is not running (ID=" + machineId
						+ ")", e);
			}
		}

		/**
		 * Get all subnets of a specific virtual network defined by its identifier passed as a
		 * parameter
		 * @param networkId virtual network identifier
		 * @return a list of virtual network subnets
		 */
		private List<Subnet> getSubnets(String networkId) {
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMSubnets").filter(
							"StampId eq guid'" + stampId + "' and VMNetworkId eq guid'" + networkId
									+ "'");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<Subnet> subnets = new ArrayList<Subnet>();
			for (ODataEntity entity : entitySet.getEntities()) {
				Subnet subnet = new Subnet();
				subnet.setName(entity.getProperty("Name").getValue().toString());
				subnet.setCidr(entity.getProperty("Subnet").getValue().toString());
				subnet.setProviderAssignedId(entity.getProperty("ID").getValue().toString());
				subnets.add(subnet);
			}

			return subnets;
		}

		/**
		 * Get the first logical network which allows virtualization
		 * @return the ID of the first logical network found allowing virtualization, or null if
		 *         none is found
		 */
		private String getNetworkAllowingVirtualization() {
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("LogicalNetworks").filter(
							"StampId eq guid'" + stampId
									+ "' and NetworkVirtualizationEnabled eq true");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			if (entitySet.getEntities().isEmpty()) {
				logger.warn("No logical network allowing virtualization detected");
				return null;
			} else {
				return entitySet.getEntities().get(0).getProperty("ID").getValue().toString();
			}
		}

		/**
		 * Creates a subnet for a specific virtual network with the configuration passed as a
		 * parameter
		 * @param subnetCreate subnet configuration
		 * @param networkId identifier of the virtual network to attached the subnet
		 * @return the subnet created
		 * @throws ConnectorException if subnet creation failed
		 */
		private Subnet createSubnet(Subnet subnetCreate, String networkId)
				throws ConnectorException {
			logger.info("Creating subnet (Name=" + subnetCreate.getName() + ", VMNetworkId="
					+ networkId + ")");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntitySetSegment("VMSubnets");

			ODataEntity subnetConfig = ODataFactory.newEntity("VMM.VMSubnet");

			// add stampId
			subnetConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add Name
			subnetConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText(subnetCreate.getName()).build()));

			// add Subnet
			subnetConfig.addProperty(ODataFactory.newPrimitiveProperty("Subnet",
					new ODataPrimitiveValue.Builder().setText(subnetCreate.getCidr()).build()));

			// add VMNetworkId
			subnetConfig.addProperty(ODataFactory.newPrimitiveProperty("VMNetworkId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(networkId)).build()));

			// create and execute request
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), subnetConfig);
			createReq.setFormat(ODataPubFormat.ATOM);

			final ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				throw new ConnectorException("Subnet creation failed: "
						+ createRes.getStatusMessage());
			}

			subnetConfig = createRes.getBody();

			logger.info("Subnet creation succeed (" + "Name="
					+ subnetConfig.getProperty("Name").getValue() + ", ID="
					+ subnetConfig.getProperty("ID").getValue() + ", VMNetworkId=" + networkId
					+ ")");

			Subnet subnet = new Subnet();
			subnet.setName(subnetConfig.getProperty("Name").getValue().toString());
			subnet.setCidr(subnetConfig.getProperty("Subnet").getValue().toString());
			subnet.setProviderAssignedId(subnetConfig.getProperty("ID").getValue().toString());

			// create static IP address pool
			createIPAddressPool(subnet);

			return subnet;
		}

		/**
		 * Creates a new static IP address pool for a specific subnet passed as a parameter
		 * @param subnet the subnet in which an new IP address pool is created
		 * @throws ConnectorException if IP address pool creation failed
		 */
		private void createIPAddressPool(Subnet subnet) throws ConnectorException {
			logger.info("Creating IP address pool (CIDR=" + subnet.getCidr() + ", Subnet="
					+ subnet.getName() + ")");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntitySetSegment("StaticIPAddressPools");

			ODataEntity ipAddressPoolConfig = ODataFactory.newEntity("VMM.StaticIPAddressPool");

			// add stampId
			ipAddressPoolConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add Name
			ipAddressPoolConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText("Default").build()));

			// add Subnet
			ipAddressPoolConfig.addProperty(ODataFactory.newPrimitiveProperty("Subnet",
					new ODataPrimitiveValue.Builder().setText(subnet.getCidr()).build()));

			// add VMSubnetId
			ipAddressPoolConfig.addProperty(ODataFactory.newPrimitiveProperty("VMSubnetId",
					new ODataPrimitiveValue.Builder().setText(subnet.getProviderAssignedId())
							.build()));

			// create and execute request
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), ipAddressPoolConfig);
			createReq.setFormat(ODataPubFormat.ATOM);

			final ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				throw new ConnectorException("IP address pool creation failed: "
						+ createRes.getStatusMessage());
			}

			ipAddressPoolConfig = createRes.getBody();

			logger.info("IP address pool creation succeed (" + "Name="
					+ ipAddressPoolConfig.getProperty("Name").getValue() + ", ID="
					+ ipAddressPoolConfig.getProperty("ID").getValue() + ", VMSubnetId="
					+ subnet.getProviderAssignedId() + ")");
		}

		/**
		 * Class used to instantiate HttpClient
		 */
		private class SimpleHttpsClientFactory implements HttpClientFactory {

			public HttpClient createHttpClient(final HttpMethod method, final URI uri) {
				SSLContext sslContext = null;
				try {
					sslContext = SSLContext.getInstance("SSL");

					sslContext.init(null, new TrustManager[] { new X509TrustManager() {
						public X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[] {};
						}

						public void checkClientTrusted(X509Certificate[] certs, String authType) {
						}

						public void checkServerTrusted(X509Certificate[] certs, String authType) {
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
							new UsernamePasswordCredentials(cloudProviderAccount.getLogin(),
									cloudProviderAccount.getPassword()));
					httpclient.addRequestInterceptor(new PreemptiveAuthInterceptor(), 0);
					return httpclient;

				} catch (Exception e) {
					e.printStackTrace();
					return null;
				}
			}

		}

		/**
		 * Class used to process HTTP request
		 */
		private static class PreemptiveAuthInterceptor implements HttpRequestInterceptor {

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
					Credentials creds = credsProvider.getCredentials(new AuthScope(targetHost
							.getHostName(), targetHost.getPort()));
					if (creds == null)
						throw new HttpException("No credentials for preemptive authentication");
					authState.update(new BasicScheme(), creds);
				}
			}

		}

	}

}
