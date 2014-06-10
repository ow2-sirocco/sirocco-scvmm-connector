package org.ow2.sirocco.cloudmanager.connector.spf;

import java.io.IOException;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
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
import org.ow2.sirocco.cloudmanager.model.cimi.PortForwardingRule;
import org.ow2.sirocco.cloudmanager.model.cimi.Subnet;
import org.ow2.sirocco.cloudmanager.model.cimi.SubnetConfig;
import org.ow2.sirocco.cloudmanager.model.cimi.Volume;
import org.ow2.sirocco.cloudmanager.model.cimi.Volume.State;
import org.ow2.sirocco.cloudmanager.model.cimi.VolumeCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.VolumeImage;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.CloudProviderAccount;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.CloudProviderLocation;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.ProviderMapping;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.Quota;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.SecurityGroup;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.SecurityGroupCreate;
import org.ow2.sirocco.cloudmanager.model.cimi.extension.SecurityGroupRule;
import org.ow2.sirocco.cloudmanager.model.utils.ResourceType;
import org.ow2.sirocco.cloudmanager.model.utils.Unit;
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
import com.msopentech.odatajclient.engine.data.ODataValue;
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

	private synchronized SPFProvider getProvider(final ProviderTarget target)
			throws ConnectorException {
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
	public void deallocateAddress(Address address, ProviderTarget target) throws ConnectorException {
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

	@Override
	public void addMachineToSecurityGroup(String arg0, String arg1, ProviderTarget arg2)
			throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public void removeMachineFromSecurityGroup(String machineId, String groupId,
			ProviderTarget target) throws ConnectorException {
		throw new ConnectorException("unsupported operation");
	}

	@Override
	public Quota getQuota(ProviderTarget target) throws ConnectorException {
		return this.getProvider(target).getQuota();
	}

	@Override
	public Address allocateAndAddAddressToMachine(String machineId, PortForwardingRule natRule,
			ProviderTarget target) throws ConnectorException {
		return this.getProvider(target).allocateAndAddAddressToMachine(machineId, natRule);
	}

	@Override
	public void removeAndReleaseAddressFromMachine(String machineId, Address address,
			ProviderTarget target) throws ConnectorException {
		this.getProvider(target).removeAndReleaseAddressFromMachine(machineId, address);
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

		private final String cloudId;

		private final String principalIdHeader;

		/**
		 * Initializes a SPF provider by instantiating a HTTP client connection with a HTTP request
		 * processing. It also queries the Stamp identifier
		 * @param cloudProviderAccount an account on a cloud provider
		 * @param cloudProviderLocation a geographical location where cloud resources are running
		 * @throws ConnectorException if a subscription ID is not found in endpoint URL
		 */
		public SPFProvider(final CloudProviderAccount cloudProviderAccount,
				final CloudProviderLocation cloudProviderLocation) throws ConnectorException {
			this.cloudProviderAccount = cloudProviderAccount;
			this.cloudProviderLocation = cloudProviderLocation;
			this.serviceRootURL = cloudProviderAccount.getCloudProvider().getEndpoint();

			// check if the endpoint URL contains a subscription ID. Endpoint format:
			// https://<SPF-Server>:8090/sc2012r2/vmm/<Subscription-ID>/microsoft.management.odata.svc/
			String subscriptionID = null;
			String[] urlSplit = serviceRootURL.split("/");
			for (int i = 0; i < urlSplit.length; i++) {
				if (urlSplit[i].toLowerCase().equals("vmm") && urlSplit[i + 1].length() == 36) {
					subscriptionID = urlSplit[i + 1];
					break;
				}
			}
			if (subscriptionID == null) {
				throw new ConnectorException("Subscription ID not found in endpoint URL");
			}

			// instantiate HTTP client connection
			Configuration.setHttpClientFactory(new SimpleHttpsClientFactory());

			/* get tenant name, stamp ID and cloud ID */

			// build admin endpoint URL from input endpoint URL (to get tenant name)
			String url = "";
			for (int i = 0; i < urlSplit.length; i++) {
				if (urlSplit[i].toLowerCase().equals("vmm")) {
					url += "admin/microsoft.management.odata.svc/";
					break;
				}
				url += urlSplit[i] + "/";
			}

			// get tenant name for principalIdHeader
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(subscriptionID));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(url).appendEntityTypeSegment(
					"Tenants").appendKeySegment(key).select("Name");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);

			final ODataRetrieveResponse<ODataEntity> res = req.execute();

			ODataEntity tenant = res.getBody();
			principalIdHeader = tenant.getProperty("Name").getValue().toString();

			logger.info("principalIdHeader=" + principalIdHeader);

			// get stamp ID and cloud ID
			final ODataURIBuilder uriBuilder2 = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("Clouds").select("ID,StampId");

			final ODataEntitySetRequest req2 = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder2.build());
			req2.setFormat(ODataPubFormat.ATOM);
			req2.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res2 = req2.execute();

			ODataEntitySet cloud = res2.getBody();
			// there is only one couple Cloud-Stamp for a tenant subscription
			cloudId = cloud.getEntities().get(0).getProperty("ID").getValue().toString();
			stampId = cloud.getEntities().get(0).getProperty("StampId").getValue().toString();

			logger.info("StampId=" + stampId);
			logger.info("CloudId=" + cloudId);
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
					.appendEntityTypeSegment("HardwareProfiles").select(
							"ID,CPUCount,Memory,Name,TotalVHDCapacity");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<MachineConfiguration> result = new ArrayList<MachineConfiguration>();
			for (ODataEntity entity : entitySet.getEntities()) {
				MachineConfiguration machineConfig = new MachineConfiguration();

				// set provider mappings
				ProviderMapping providerMapping = new ProviderMapping();
				providerMapping.setProviderAssignedId(entity.getProperty("ID").getValue()
						.toString());
				providerMapping.setProviderAccount(this.cloudProviderAccount);
				machineConfig.setProviderMappings(Collections.singletonList(providerMapping));

				// set name
				machineConfig.setName(entity.getProperty("Name").getValue().toString());

				// set cpu
				machineConfig.setCpu(entity.getProperty("CPUCount").getValue().asPrimitive()
						.<Integer> toCastValue());

				// set memory
				machineConfig.setMemory(entity.getProperty("Memory").getValue().asPrimitive()
						.<Integer> toCastValue() * 1024); // MB to KB

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

			// add StampId
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add cloud id
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("CloudId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(cloudId)).build()));

			// add VM name
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText(machineCreate.getName()).setType(
							EdmSimpleType.String).build()));

			// add computer name
			String computerName = machineCreate.getName();
			// maximum computer name length allowed is 15
			if (computerName.length() > 15) {
				computerName = computerName.substring(0, 15);
				logger.warn("Computer name exceeds maximum allowed length of 15. It has been truncated.");
			}
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("ComputerName",
					new ODataPrimitiveValue.Builder().setText(computerName).setType(
							EdmSimpleType.String).build()));

			// get number of CPU and amount of memory from MachineConfiguration ID
			ProviderMapping mapping = ProviderMapping.find(machineCreate.getMachineTemplate()
					.getMachineConfig(), cloudProviderAccount, cloudProviderLocation);
			if (mapping == null) {
				throw new ResourceNotFoundException("Cannot find machine config ID of "
						+ machineCreate.getMachineTemplate().getMachineConfig().getName());
			}
			String hardwareProfileId = mapping.getProviderAssignedId();
			MachineConfiguration machineConfiguration = getMachineConfiguration(hardwareProfileId);

			// add number of CPU
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("CPUCount",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Byte).setValue(
							machineConfiguration.getCpu()).build()));

			// add amount of memory
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("Memory",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Byte).setValue(
							machineConfiguration.getMemory() / 1024).build()));

			// add VirtualHardDiskId
			mapping = ProviderMapping.find(machineCreate.getMachineTemplate().getMachineImage(),
					cloudProviderAccount, cloudProviderLocation);
			if (mapping == null) {
				throw new ResourceNotFoundException("Cannot find machine image ID of "
						+ machineCreate.getMachineTemplate().getMachineImage().getName());
			}
			String vhdId = mapping.getProviderAssignedId();
			machineConfig.addProperty(ODataFactory.newPrimitiveProperty("VirtualHardDiskId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(vhdId)).build()));

			// add NewVirtualNetworkAdapterInput
			ODataCollectionValue collection = new ODataCollectionValue(
					"Collection(VMM.NewVMVirtualNetworkAdapterInput)");

			if (machineCreate.getMachineTemplate().getNetworkInterfaces() != null) {
				for (MachineTemplateNetworkInterface nic : machineCreate.getMachineTemplate()
						.getNetworkInterfaces()) {

					ODataComplexValue nicOData = new ODataComplexValue(
							"NewVMVirtualNetworkAdapterInput");

					ODataEntity network = getNetworkFromId(nic.getNetwork().getProviderAssignedId());

					nicOData.add(ODataFactory.newPrimitiveProperty("VMNetworkName",
							new ODataPrimitiveValue.Builder().setText(
									network.getProperty("Name").getValue().toString()).setType(
									EdmSimpleType.String).build()));

					// set IPv4 and MAC addresses type to static for virtualized network
					if (network.getProperty("IsolationType").getValue().toString().equals(
							"WindowsNetworkVirtualization")) {
						nicOData.add(ODataFactory.newPrimitiveProperty("MACAddressType",
								new ODataPrimitiveValue.Builder().setText("Static").setType(
										EdmSimpleType.String).build()));
						nicOData.add(ODataFactory.newPrimitiveProperty("IPv4AddressType",
								new ODataPrimitiveValue.Builder().setText("Static").setType(
										EdmSimpleType.String).build()));
					}

					collection.add(nicOData);
				}
			}

			machineConfig.addProperty(ODataFactory.newCollectionProperty(
					"NewVirtualNetworkAdapterInput", collection));

			// add user account credentials of the local administrator
			if (machineCreate.getMachineTemplate().getCredential() != null) {

				// field credentials
				String adminUserName = machineCreate.getMachineTemplate().getCredential()
						.getUserName();
				String adminPassword = machineCreate.getMachineTemplate().getCredential()
						.getPassword();

				// add public key for Linux SSH
				String publicKey = machineCreate.getMachineTemplate().getCredential()
						.getPublicKey();
				if (publicKey != null) {
					machineConfig.addProperty(ODataFactory.newPrimitiveProperty(
							"LinuxAdministratorSSHKeyString", new ODataPrimitiveValue.Builder()
									.setText(publicKey).setType(EdmSimpleType.String).build()));

					// set credentials if not defined
					if (adminUserName == null || adminUserName.isEmpty()) {
						adminUserName = "root";
					}
					if (adminPassword == null || adminPassword.isEmpty()) {
						adminPassword = "change-me";
					}
				}

				// add user name
				if (adminUserName != null && !adminUserName.isEmpty()) {
					machineConfig.addProperty(ODataFactory.newPrimitiveProperty(
							"LocalAdminUserName", new ODataPrimitiveValue.Builder().setText(
									adminUserName).setType(EdmSimpleType.String).build()));
				}

				// add password
				if (adminPassword != null && !adminPassword.isEmpty()) {
					machineConfig.addProperty(ODataFactory.newPrimitiveProperty(
							"LocalAdminPassword", new ODataPrimitiveValue.Builder().setText(
									adminPassword).setType(EdmSimpleType.String).build()));
				}

			}

			// create and execute request
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), machineConfig);
			createReq.setFormat(ODataPubFormat.ATOM);
			createReq.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key).select(
							"ID,Name,Status,CPUCount,Memory");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

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

		/**
		 * Returns all VMM virtual hard disks
		 * @param returnAccountImagesOnly never used
		 * @param searchCriteria never used
		 * @return a list of all virtual machine images
		 */
		public List<MachineImage> getMachineImages(final boolean returnAccountImagesOnly,
				final Map<String, String> searchCriteria) throws ConnectorException {
			logger.info("Getting machine images");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualHardDisks").select(
							"ID,Name,State,Location,OperatingSystemInstance");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<MachineImage> result = new ArrayList<MachineImage>();

			for (ODataEntity vhd : entitySet.getEntities()) {
				MachineImage machineImage = new MachineImage();
				// set name
				machineImage.setName(vhd.getProperty("Name").getValue().toString());
				// set state
				if (vhd.getProperty("State").getValue().toString().equals("Normal")) {
					machineImage.setState(MachineImage.State.AVAILABLE);
				} else {
					logger.warn("Unkown machine image state: "
							+ vhd.getProperty("State").getValue().toString());
					machineImage.setState(MachineImage.State.UNKNOWN);
				}
				// set type
				machineImage.setType(MachineImage.Type.IMAGE);
				// set provider mappings
				ProviderMapping providerMapping = new ProviderMapping();
				providerMapping.setProviderAssignedId(vhd.getProperty("ID").getValue().toString());
				providerMapping.setProviderAccount(cloudProviderAccount);
				providerMapping.setProviderLocation(cloudProviderLocation);
				machineImage.setProviderMappings(Collections.singletonList(providerMapping));
				// set image location
				machineImage.setImageLocation(vhd.getProperty("Location").getValue().toString());
				// set architecture
				machineImage.setArchitecture(vhd.getProperty("OperatingSystemInstance")
						.getComplexValue().get("Architecture").getValue().toString());
				// set OS type
				machineImage.setOsType(vhd.getProperty("OperatingSystemInstance").getComplexValue()
						.get("OSType").getValue().toString());

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

		/**
		 * Deletes a virtual network defined by its ID
		 * @param networkId virtual network identifier
		 * @throws ConnectorException if the network deletion failed
		 */
		public void deleteNetwork(final String networkId) throws ConnectorException {
			logger.info("Deleting network (ID=" + networkId + ")");

			// deleting subnets
			for (Subnet subnet : getSubnets(networkId)) {
				deleteSubnet(subnet.getProviderAssignedId());
			}

			// deleting network
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(networkId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMNetworks").appendKeySegment(key);

			final ODataDeleteRequest req = ODataCUDRequestFactory.getDeleteRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataDeleteResponse res = req.execute();

			// response processing
			if (res.getStatusCode() != 204) {
				throw new ConnectorException("Network deletion failed (HTTP status: "
						+ res.getStatusCode() + "):" + res.getStatusMessage());
			}

			logger.info("Network deletion succeed (ID=" + networkId + ")");
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
					.appendEntityTypeSegment("VMNetworks").appendKeySegment(key).select(
							"ID,Name,Enabled");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
			createReq.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
			for (SubnetConfig subnetConfig : networkCreate.getNetworkTemplate().getNetworkConfig()
					.getSubnets()) {
				createSubnet(subnetConfig, networkConfig.getProperty("ID").getValue().toString());
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
					.appendEntityTypeSegment("VMNetworks").select("ID,Name,Enabled");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<Network> result = new ArrayList<>();
			for (ODataEntity entity : entitySet.getEntities()) {
				result.add(fromODataNetworkToCimiNetwork(entity));
			}

			logger.info("Number of networks: " + result.size());

			return result;
		}

		/**
		 * Returns quota and usage resources for a user. Resources are virtual machines, vCPUs,
		 * memory (MB) and storage (GB)
		 * @return quota and usage resources for a user
		 */
		public Quota getQuota() {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(cloudId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("Clouds").appendKeySegment(key)
					.appendEntityTypeSegment("QuotaAndUsageComponents").select(
							"QuotaDimension,UserRoleQuota,UserRoleUsage");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			Quota quota = new Quota();
			List<Quota.Resource> resourceQuotas = new ArrayList<Quota.Resource>();
			quota.setResources(resourceQuotas);
			for (ODataEntity entity : res.getBody().getEntities()) {
				Quota.Resource resourceQuota = null;
				switch (entity.getProperty("QuotaDimension").getValue().toString()) {
				case "VMCount":
					resourceQuota = new Quota.Resource(ResourceType.VIRTUAL_MACHINE, Unit.COUNT);
					break;
				case "CpuCount":
					resourceQuota = new Quota.Resource(ResourceType.CPU, Unit.COUNT);
					break;
				case "MemoryMB":
					resourceQuota = new Quota.Resource(ResourceType.MEMORY, Unit.MEGABYTE);
					break;
				case "StorageGB":
					resourceQuota = new Quota.Resource(ResourceType.DISK_SPACE, Unit.GIGABYTE);
					break;
				}
				if (resourceQuota != null) {
					if (entity.getProperty("UserRoleQuota").getValue() == null) {
						resourceQuota.setLimit(-1);
					} else {
						resourceQuota.setLimit(entity.getProperty("UserRoleQuota").getValue()
								.asPrimitive().<Integer> toCastValue());
					}
					if (entity.getProperty("UserRoleUsage").getValue() == null) {
						resourceQuota.setUsed(-1);
					} else {
						resourceQuota.setUsed(entity.getProperty("UserRoleUsage").getValue()
								.asPrimitive().<Integer> toCastValue());
					}
					resourceQuotas.add(resourceQuota);
				}
			}

			return quota;
		}

		/**
		 * Creates a NAT rule to access a specific VM through a gateway. A NAT rule is an IP and
		 * port forwarding between a virtual network (external IP and port) and a VM connected to
		 * that network (internal IP and port).<br>
		 * Internal IP and port are passed as parameter through <code>PortForwardingRule</code>
		 * object. External IP and port are given in output through <code>Address</code> object.<br>
		 * The external port is the next available port from all VM network NAT rules. By default it
		 * starts from 20000.
		 * @param machineId virtual machine identifier
		 * @param natRule port forwarding rule containing internal IP and port of the VM
		 * @return public address IP object containing the new NAT rule
		 * @throws ConnectorException if the VM network is not found or is not connected to a
		 *         gateway
		 */
		public Address allocateAndAddAddressToMachine(String machineId, PortForwardingRule natRule)
				throws ConnectorException {

			/* Allocate IP address to machine */

			// get the ID of the network attached to the VM
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key)
					.appendEntityTypeSegment("VirtualNetworkAdapters").select(
							"VMNetworkId,IPv4Addresses");

			ODataEntitySetRequest req = ODataRetrieveRequestFactory.getEntitySetRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			ODataRetrieveResponse<ODataEntitySet> res = req.execute();

			// loop entities to find the correct network
			// if the VM internal IP is null, we choose the first network found
			String networkId = null;
			if (natRule.getInternalIp() == null) {
				ODataEntity nic = res.getBody().getEntities().get(0);
				networkId = nic.getProperty("VMNetworkId").toString();
				natRule.setInternalIp(nic.getProperty("IPv4Addresses").getCollectionValue()
						.iterator().next().toString());
			} else {
				boolean found = false;
				for (ODataEntity entity : res.getBody().getEntities()) {
					for (Iterator<ODataValue> iterator = entity.getProperty("IPv4Addresses")
							.getCollectionValue().iterator(); iterator.hasNext();) {
						if (iterator.next().toString().equals(natRule.getInternalIp())) {
							networkId = entity.getProperty("VMNetworkId").getValue().toString();
							found = true;
							break;
						}
					}
					if (found) {
						break;
					}
				}
			}
			if (networkId == null) {
				throw new ConnectorException("VM network not found");
			}

			// get the ID of the gateway connected to the network
			key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(networkId));
			key.put("StampId", UUID.fromString(stampId));
			uriBuilder = new ODataURIBuilder(serviceRootURL).appendEntityTypeSegment("VMNetworks")
					.appendKeySegment(key).appendEntityTypeSegment("VMNetworkGateways")
					.select("ID");

			req = ODataRetrieveRequestFactory.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			res = req.execute();
			if (res.getBody().getEntities().isEmpty()) {
				throw new ConnectorException("The network '" + networkId
						+ "' is not connected to a gateway");
			}
			String networkGatewayID = res.getBody().getEntities().get(0).getProperty("ID")
					.getValue().toString();

			// get the ID of the gateway NAT connection
			key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(networkGatewayID));
			key.put("StampId", UUID.fromString(stampId));
			uriBuilder = new ODataURIBuilder(serviceRootURL).appendEntityTypeSegment(
					"VMNetworkGateways").appendKeySegment(key).appendEntityTypeSegment(
					"NATConnections").select("ID");

			req = ODataRetrieveRequestFactory.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			res = req.execute();
			String natConnectionId = res.getBody().getEntities().get(0).getProperty("ID")
					.getValue().toString();

			// get NAT rules
			key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(natConnectionId));
			key.put("StampId", UUID.fromString(stampId));
			uriBuilder = new ODataURIBuilder(serviceRootURL).appendEntityTypeSegment(
					"NATConnections").appendKeySegment(key).appendEntityTypeSegment("Rules")
					.select("ExternalIPAddress,ExternalPort");

			req = ODataRetrieveRequestFactory.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			res = req.execute();

			// get next available port
			int portMax = 0;
			for (ODataEntity entity : res.getBody().getEntities()) {
				int port = entity.getProperty("ExternalPort").getValue().asPrimitive()
						.<Integer> toCastValue();
				if (port > portMax) {
					portMax = port;
				}
			}

			// increment port or set it to 20000 if no rules exist
			if (portMax == 0) {
				portMax = 20000;
			} else {
				portMax++;
			}

			/* Add IP address to machine */

			// create NAT rule
			ODataEntity natRuleConfig = ODataFactory.newEntity("VMM.NATRule");

			// add StampId
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add NATConnectionId
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("NATConnectionId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(natConnectionId)).build()));

			// add Name
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder().setText(machineId).build()));

			// add Protocol
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("Protocol",
					new ODataPrimitiveValue.Builder().setText("TCP").build()));

			// add ExternalPort
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("ExternalPort",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Int32)
							.setValue(portMax).build()));

			// add InternalIPAddress
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("InternalIPAddress",
					new ODataPrimitiveValue.Builder().setText(natRule.getInternalIp()).build()));

			// add InternalPort
			natRuleConfig.addProperty(ODataFactory.newPrimitiveProperty("InternalPort",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Int32).setValue(
							natRule.getInternalPort()).build()));

			// create and execute request
			uriBuilder = new ODataURIBuilder(serviceRootURL).appendEntitySetSegment("NATRules");
			ODataEntityCreateRequest createReq = ODataCUDRequestFactory.getEntityCreateRequest(
					uriBuilder.build(), natRuleConfig);
			createReq.setFormat(ODataPubFormat.ATOM);
			createReq.addCustomHeader("x-ms-principal-id", principalIdHeader);

			ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				throw new ConnectorException("NAT rule creation failed: "
						+ createRes.getStatusMessage());
			}

			natRuleConfig = createRes.getBody();

			logger.info("NAT rule creation succeed (Name="
					+ natRuleConfig.getProperty("Name").getValue() + ", ExternalIPAddress="
					+ natRuleConfig.getProperty("ExternalIPAddress").getValue() + ", ExternalPort="
					+ natRuleConfig.getProperty("ExternalPort").getValue() + ", InternalIPAddress="
					+ natRuleConfig.getProperty("InternalIPAddress").getValue() + ", InternalPort="
					+ natRuleConfig.getProperty("InternalPort").getValue() + ")");

			// add external IP and port to PortForwardingRule object
			natRule.setExternalIp(natRuleConfig.getProperty("ExternalIPAddress").getValue()
					.toString());
			natRule.setExternalPort(natRuleConfig.getProperty("ExternalPort").getValue()
					.asPrimitive().<Integer> toCastValue());

			// build address to return
			Address address = new Address();
			address.setIp(natRule.getExternalIp());
			address.setPortForwardingRule(natRule);
			address.setProtocol("IPv4");

			return address;
		}

		public void removeAndReleaseAddressFromMachine(String machineId, Address address)
				throws ConnectorException {
			// TODO Auto-generated method stub

		}

		//
		// OData functions
		//

		/**
		 * Retrieves network properties with its identifier
		 * @param networkId network identifier
		 * @return network name and isolation type depending on the network identifier passed as a
		 *         parameter
		 * @throws ResourceNotFoundException if the requested network does not exist
		 * @throws ConnectorException if a client error in OData occurs
		 */
		private ODataEntity getNetworkFromId(String networkId) throws ResourceNotFoundException,
				ConnectorException {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(networkId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMNetworks").appendKeySegment(key).select(
							"Name,IsolationType");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();

				return res.getBody();

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

			// set operation
			machine.addProperty(ODataFactory.newPrimitiveProperty("Operation",
					new ODataPrimitiveValue.Builder().setText(machineAction.action).setType(
							EdmSimpleType.String).build()));

			final ODataEntityUpdateRequest req = ODataCUDRequestFactory.getEntityUpdateRequest(
					uriBuilder.build(), UpdateType.REPLACE, machine);
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
			machine.setMemory(entity.getProperty("Memory").getValue().asPrimitive()
					.<Integer> toCastValue() * 1024); // MB to KB

			// set disks
			machine.setDisks(getVirtualHardDisks(machineId));

			// set nics
			boolean ipAddressesUnavailable = false;
			List<MachineNetworkInterface> nics = new ArrayList<MachineNetworkInterface>();
			for (ODataEntity odataNetwork : getVirtualNetworkAdapters(machineId).getEntities()) {
				if (odataNetwork.getProperty("VMNetworkId").hasNullValue()) {
					break;
				}
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

				// set state
				if (odataNetwork.getProperty("Enabled").getValue().asPrimitive()
						.<Boolean> toCastValue()) {
					nic.setState(MachineNetworkInterface.InterfaceState.ACTIVE);
				} else {
					nic.setState(MachineNetworkInterface.InterfaceState.DISABLED);
				}

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

			// set network state
			if (odataNetworkAdapter.getProperty("Enabled").getValue().asPrimitive()
					.<Boolean> toCastValue()) {
				cimiNetwork.setState(Network.State.STARTED);
			} else {
				cimiNetwork.setState(Network.State.STOPPED);
			}

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

			// set network state
			if (odataNetwork.getProperty("Enabled").getValue().asPrimitive()
					.<Boolean> toCastValue()) {
				cimiNetwork.setState(Network.State.STARTED);
			} else {
				cimiNetwork.setState(Network.State.STOPPED);
			}

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
		private List<MachineDisk> getVirtualHardDisks(String machineId) {
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(machineId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VirtualMachines").appendKeySegment(key)
					.appendEntityTypeSegment("VirtualHardDisks").select("Name,Size");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();

			List<MachineDisk> machineDisks = new ArrayList<MachineDisk>();
			for (ODataEntity vhd : res.getBody().getEntities()) {
				MachineDisk machineDisk = new MachineDisk();
				// set disk name
				machineDisk.setName(vhd.getProperty("Name").getValue().toString());
				// set disk capacity
				Long capacity = vhd.getProperty("Size").getValue().asPrimitive()
						.<Long> toCastValue() / 1024; // Byte to KB
				machineDisk.setCapacity(capacity.intValue());
				machineDisks.add(machineDisk);
			}

			return machineDisks;
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
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			// TODO filter + return MachineNetworkInterface object
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
					.appendEntityTypeSegment("GuestInfos").appendKeySegment(key).select(
							"IPv4Addresses,IPv6Addresses");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			try {
				final ODataRetrieveResponse<ODataEntity> res = req.execute();
				final ODataEntity entity = res.getBody();

				List<MachineNetworkInterfaceAddress> nicAddresses = new ArrayList<MachineNetworkInterfaceAddress>();
				// IPv4Addresses
				String[] ipv4Addresses = entity.getProperty("IPv4Addresses").getValue().toString()
						.split(";");
				for (String ipv4Address : ipv4Addresses) {
					if (ipv4Address.equals("127.0.0.1")) {
						continue;
					}
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
					if (ipv6Address.equals("::1")) {
						continue;
					}
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
				throw new BadStateException(
						"Unable to get VM IP addresses because the VM is not running (ID="
								+ machineId + ")", e);
			} catch (NullPointerException e) {
				throw new BadStateException(
						"Unable to get VM IP addresses because the VM is not running (ID="
								+ machineId + ")", e);
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
									+ "'").select("ID,Name,Subnet");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
									+ "' and NetworkVirtualizationEnabled eq true").select("ID");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			if (entitySet.getEntities().isEmpty()) {
				logger.error("No logical network allowing virtualization detected");
				return null;
			} else {
				return entitySet.getEntities().get(0).getProperty("ID").getValue().toString();
			}
		}

		/**
		 * Creates a subnet for a specific virtual network with the configuration passed as a
		 * parameter
		 * @param subnetConfig subnet configuration
		 * @param networkId identifier of the virtual network to attached the subnet
		 * @return the subnet created
		 * @throws ConnectorException if subnet creation failed
		 */
		private Subnet createSubnet(SubnetConfig subnetConfig, String networkId)
				throws ConnectorException {
			logger.info("Creating subnet (Name=" + subnetConfig.getName() + ", VMNetworkId="
					+ networkId + ")");

			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntitySetSegment("VMSubnets");

			ODataEntity subnetSPF = ODataFactory.newEntity("VMM.VMSubnet");

			// add stampId
			subnetSPF.addProperty(ODataFactory.newPrimitiveProperty("StampId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(stampId)).build()));

			// add Name
			subnetSPF.addProperty(ODataFactory.newPrimitiveProperty("Name",
					new ODataPrimitiveValue.Builder()
							.setText(
									(subnetConfig.getName() == null || subnetConfig.getName()
											.isEmpty()) ? "DefaultSubnet" : subnetConfig.getName())
							.build()));

			// add Subnet
			subnetSPF.addProperty(ODataFactory.newPrimitiveProperty("Subnet",
					new ODataPrimitiveValue.Builder().setText(subnetConfig.getCidr()).build()));

			// add VMNetworkId
			subnetSPF.addProperty(ODataFactory.newPrimitiveProperty("VMNetworkId",
					new ODataPrimitiveValue.Builder().setType(EdmSimpleType.Guid).setValue(
							UUID.fromString(networkId)).build()));

			// create and execute request
			final ODataEntityCreateRequest createReq = ODataCUDRequestFactory
					.getEntityCreateRequest(uriBuilder.build(), subnetSPF);
			createReq.setFormat(ODataPubFormat.ATOM);
			createReq.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataEntityCreateResponse createRes = createReq.execute();

			// response processing
			if (createRes.getStatusCode() != 201) {
				throw new ConnectorException("Subnet creation failed: "
						+ createRes.getStatusMessage());
			}

			subnetSPF = createRes.getBody();

			logger.info("Subnet creation succeed (" + "Name="
					+ subnetSPF.getProperty("Name").getValue() + ", ID="
					+ subnetSPF.getProperty("ID").getValue() + ", VMNetworkId=" + networkId + ")");

			Subnet subnet = new Subnet();
			subnet.setName(subnetSPF.getProperty("Name").getValue().toString());
			subnet.setCidr(subnetSPF.getProperty("Subnet").getValue().toString());
			subnet.setProviderAssignedId(subnetSPF.getProperty("ID").getValue().toString());

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
			createReq.addCustomHeader("x-ms-principal-id", principalIdHeader);

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
		 * Deletes an IP address pool defined by its ID
		 * @param ipPoolId IP address pool identifier
		 * @throws ConnectorException if the address pool deletion failed
		 */
		private void deleteIPAddressPool(String ipPoolId) throws ConnectorException {
			logger.info("Deleting IP address pool (ID=" + ipPoolId + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(ipPoolId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("StaticIPAddressPools").appendKeySegment(key);

			final ODataDeleteRequest req = ODataCUDRequestFactory.getDeleteRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataDeleteResponse res = req.execute();

			// response processing
			if (res.getStatusCode() != 204) {
				throw new ConnectorException("IP address pool deletion failed (HTTP status: "
						+ res.getStatusCode() + "):" + res.getStatusMessage());
			}

			logger.info("IP address pool deletion succeed (ID=" + ipPoolId + ")");
		}

		/**
		 * Gets all IP address pools for a subnet
		 * @param subnetId subnet identifier
		 * @return a list of IP address pools identifier
		 */
		private List<String> getIPAddressPools(String subnetId) {
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("StaticIPAddressPools").filter(
							"StampId eq guid'" + stampId + "' and VMSubnetId eq guid'" + subnetId
									+ "'").select("ID");

			final ODataEntitySetRequest req = ODataRetrieveRequestFactory
					.getEntitySetRequest(uriBuilder.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntitySet> res = req.execute();
			final ODataEntitySet entitySet = res.getBody();

			List<String> ipPools = new ArrayList<String>();
			for (ODataEntity entity : entitySet.getEntities()) {
				ipPools.add(entity.getProperty("ID").getValue().toString());
			}

			return ipPools;
		}

		/**
		 * Deletes a subnet defined by its ID
		 * @param subnetId subnet identifier
		 * @throws ConnectorException if the subnet deletion failed
		 */
		private void deleteSubnet(String subnetId) throws ConnectorException {
			logger.info("Deleting subnet (ID=" + subnetId + ")");

			// deleting IP address pools
			for (String ipPoolId : getIPAddressPools(subnetId)) {
				deleteIPAddressPool(ipPoolId);
			}

			// deleting subnet
			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(subnetId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("VMSubnets").appendKeySegment(key);

			final ODataDeleteRequest req = ODataCUDRequestFactory.getDeleteRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataDeleteResponse res = req.execute();

			// response processing
			if (res.getStatusCode() != 204) {
				throw new ConnectorException("Subnet deletion failed (HTTP status: "
						+ res.getStatusCode() + "):" + res.getStatusMessage());
			}

			logger.info("Subnet deletion succeed (ID=" + subnetId + ")");
		}

		/**
		 * Returns VMM hardware profile defined by its ID
		 * @param hardwareProfileId VMM hardware profile identifier
		 * @return a the machine configuration (CPU and memory) requested
		 */
		private MachineConfiguration getMachineConfiguration(String hardwareProfileId) {
			logger.info("Getting machine config (ID=" + hardwareProfileId + ")");

			Map<String, Object> key = new HashMap<String, Object>();
			key.put("ID", UUID.fromString(hardwareProfileId));
			key.put("StampId", UUID.fromString(stampId));
			final ODataURIBuilder uriBuilder = new ODataURIBuilder(serviceRootURL)
					.appendEntityTypeSegment("HardwareProfiles").appendKeySegment(key).select(
							"CPUCount,Memory");

			final ODataEntityRequest req = ODataRetrieveRequestFactory.getEntityRequest(uriBuilder
					.build());
			req.setFormat(ODataPubFormat.ATOM);
			req.addCustomHeader("x-ms-principal-id", principalIdHeader);

			final ODataRetrieveResponse<ODataEntity> res = req.execute();
			final ODataEntity entity = res.getBody();

			MachineConfiguration machineConfig = new MachineConfiguration();

			// set cpu
			machineConfig.setCpu(entity.getProperty("CPUCount").getValue().asPrimitive()
					.<Integer> toCastValue());

			// set memory
			machineConfig.setMemory(entity.getProperty("Memory").getValue().asPrimitive()
					.<Integer> toCastValue() * 1024); // MB to KB

			return machineConfig;
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
