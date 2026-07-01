package org.fog.test.perfeval;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.cloudbus.cloudsim.Host;
import org.cloudbus.cloudsim.Log;
import org.cloudbus.cloudsim.Pe;
import org.cloudbus.cloudsim.Storage;
import org.cloudbus.cloudsim.core.CloudSim;
import org.cloudbus.cloudsim.power.PowerHost;
import org.cloudbus.cloudsim.provisioners.RamProvisionerSimple;
import org.cloudbus.cloudsim.sdn.overbooking.BwProvisionerOverbooking;
import org.cloudbus.cloudsim.sdn.overbooking.PeProvisionerOverbooking;
import org.fog.application.AppEdge;
import org.fog.application.AppLoop;
import org.fog.application.Application;
import org.fog.application.selectivity.FractionalSelectivity;
import org.fog.entities.Actuator;
import org.fog.entities.FogBroker;
import org.fog.entities.FogDevice;
import org.fog.entities.FogDeviceCharacteristics;
import org.fog.entities.Sensor;
import org.fog.entities.Tuple;
import org.fog.placement.Controller;
import org.fog.placement.ModuleMapping;
import org.fog.placement.ModulePlacementEdgewards;
import org.fog.policy.AppModuleAllocationPolicy;
import org.fog.scheduler.StreamOperatorScheduler;
import org.fog.utils.FogLinearPowerModel;
import org.fog.utils.FogUtils;
import org.fog.utils.TimeKeeper;
import org.fog.utils.distribution.UniformDistribution;

/**
 * Fog Computing Simulation for Post-Quantum IoT Authentication Architecture
 *
 * Experiment 5: iFogSim-based Fog Computing Performance Evaluation
 *
 * Architecture: All-UP pipeline to avoid iFogSim's DOWN-broadcast amplification.
 *   SENSOR → crypto_signer (IoT) → sig_verifier (Edge) → did_resolver (Relay)
 *   → onchain_verifier (Cloud) → auth_decision (Cloud) → ACTUATOR (Cloud)
 *
 * Network latency is modeled as doubled per-hop values (round-trip equivalent):
 *   sensor→IoT: 4ms, IoT→Edge: 20ms, Edge→Relay: 40ms, Relay→Cloud: 100ms
 *   Total one-way: 164ms (models full uplink + downlink round-trip)
 *
 * MI Calibration:
 *   MI = t_benchmark_ms * 10000 (single i9-14900K P-core est. MIPS for crypto)
 *   Processing time on device = MI / MIPS_device
 *
 * Usage: java PQCFogAuthentication [numIoTs] [scheme] [simTime] [placementMode]
 *   scheme: "falcon" (default), "ecdsa", or "dilithium2"
 *   simTime: simulation duration in seconds (default 1000)
 *   placementMode: "fog" (default, edgewards) or "cloud" (all modules on cloud)
 */
public class PQCFogAuthentication {

	static List<FogDevice> fogDevices = new ArrayList<FogDevice>();
	static List<Sensor> sensors = new ArrayList<Sensor>();
	static List<Actuator> actuators = new ArrayList<Actuator>();

	static int numOfIoTDevices = 10;
	static int numOfEdgeGateways = 2;
	static int numOfRelays = 1;

	static double simulationTime = 1000.0;
	static String cryptoScheme = "falcon";
	static String placementMode = "fog"; // "fog" (edgewards) or "cloud" (all modules on cloud)

	// ---- MI calibrated from Exp1 benchmarks ----
	// MI = time_ms * 10000
	// Exp1 IoT Docker results (1000 iterations each):
	//   Falcon-512:     sign=0.154ms, verify=0.037ms
	//   ECDSA:          sign=0.600ms, verify=0.217ms
	//   Dilithium2:     sign=0.064ms, verify=0.031ms

	// Falcon-512 MI values
	static double FALCON_SIGN_MI = 1540;      // 0.154ms * 10000
	static double FALCON_VERIFY_MI = 370;     // 0.037ms * 10000
	static double FALCON_PK_SIZE = 897;
	static double FALCON_SIG_SIZE = 666;

	// ECDSA (secp256k1) MI values
	static double ECDSA_SIGN_MI = 6000;       // 0.600ms * 10000
	static double ECDSA_VERIFY_MI = 2170;     // 0.217ms * 10000
	static double ECDSA_PK_SIZE = 64;
	static double ECDSA_SIG_SIZE = 64;

	// Dilithium2 / ML-DSA-44 MI values
	static double DILITHIUM2_SIGN_MI = 640;   // 0.064ms * 10000
	static double DILITHIUM2_VERIFY_MI = 310; // 0.031ms * 10000
	static double DILITHIUM2_PK_SIZE = 1312;
	static double DILITHIUM2_SIG_SIZE = 2420;

	// Common costs
	static double DID_RESOLVE_MI = 200;       // DID doc lookup + hash
	static double BLOCKCHAIN_VERIFY_MI = 2000;// Smart contract execution
	static double SENSOR_DATA_SIZE = 200;     // bytes - raw sensor data

	// ---- Device configurations ----
	static final long   IOT_MIPS = 100;
	static final int    IOT_RAM = 256;
	static final double IOT_BUSY_W = 0.5;     // ESP32-S3 class
	static final double IOT_IDLE_W = 0.1;

	static final long   EDGE_MIPS = 6000;
	static final int    EDGE_RAM = 4096;
	static final double EDGE_BUSY_W = 15.0;   // Raspberry Pi 4 class
	static final double EDGE_IDLE_W = 5.0;

	static final long   RELAY_MIPS = 4000;
	static final int    RELAY_RAM = 8192;
	static final double RELAY_BUSY_W = 50.0;  // Entry-level server
	static final double RELAY_IDLE_W = 20.0;

	static final long   CLOUD_MIPS = 20000;
	static final int    CLOUD_RAM = 16384;
	static final double CLOUD_BUSY_W = 300.0; // Data-center server
	static final double CLOUD_IDLE_W = 100.0;

	// ---- Network bandwidth (Bps) ----
	// Simulation bandwidth: set very high (100 Gbps) so iFogSim's link-busy
	// model does not add bandwidth-dependent transmission delay.  Bandwidth
	// delay is computed analytically (see bw_delay_ms in output) based on
	// realistic link speeds (see ANALYTICAL_* constants below).
	static final long   IOT_UP_BW = 12500000000L;
	static final long   IOT_DOWN_BW = 12500000000L;
	static final long   EDGE_UP_BW = 12500000000L;
	static final long   EDGE_DOWN_BW = 12500000000L;
	static final long   RELAY_UP_BW = 12500000000L;
	static final long   RELAY_DOWN_BW = 12500000000L;
	static final long   CLOUD_UP_BW = 12500000000L;
	static final long   CLOUD_DOWN_BW = 12500000000L;

	// Analytical reference bandwidth for BW delay calculation (realistic IoT fog speeds)
	//   IoT→Edge:  BLE 5.0  ~1 Mbps  = 125,000 Bps
	//   Edge→Relay: WiFi     ~10 Mbps = 1,250,000 Bps
	//   Relay→Cloud: Eth     ~50 Mbps = 6,250,000 Bps
	//   Cloud: DC             ~500 Mbps= 62,500,000 Bps
	static final long   ANALYTICAL_IOT_BW = 125000;
	static final long   ANALYTICAL_EDGE_BW = 1250000;
	static final long   ANALYTICAL_RELAY_BW = 6250000;

	// Network latency per hop (doubled to model full round-trip in all-UP pipeline)
	// Original one-way: sensor→IoT=2ms, IoT→Edge=10ms, Edge→Relay=20ms, Relay→Cloud=50ms
	// Round-trip equivalent: sensor→IoT=4ms, IoT→Edge=20ms, Edge→Relay=40ms, Relay→Cloud=100ms
	static final double SENSOR_NET_LATENCY = 4.0;   // was 2ms, now 4ms
	static final double IOT_UPLINK_LATENCY = 20.0;   // was 10ms, now 20ms
	static final double EDGE_UPLINK_LATENCY = 40.0;   // was 20ms, now 40ms
	static final double RELAY_UPLINK_LATENCY = 100.0;  // was 50ms, now 100ms

	public static void main(String[] args) {
		// Force auto-flush on stdout to prevent buffering when output is piped/redirected
		System.setOut(new java.io.PrintStream(System.out, true));

		if (args.length >= 1) numOfIoTDevices = Integer.parseInt(args[0]);
		if (args.length >= 2) cryptoScheme = args[1].toLowerCase();
		if (args.length >= 3) simulationTime = Double.parseDouble(args[2]);
		if (args.length >= 4) placementMode = args[3].toLowerCase(); // "fog" or "cloud"

		numOfEdgeGateways = Math.max(2, numOfIoTDevices / 5);
		numOfRelays = Math.max(1, numOfEdgeGateways / 4);

		System.out.println("=== Fog Simulation Configuration ===");
		System.out.println("Scheme: " + cryptoScheme.toUpperCase());
		System.out.println("Placement: " + placementMode);
		System.out.println("IoT Devices: " + numOfIoTDevices);
		System.out.println("Edge Gateways: " + numOfEdgeGateways);
		System.out.println("Relays: " + numOfRelays);
		System.out.println("Simulation Time: " + simulationTime + "s");
		System.out.println("=====================================");

		Log.disable();

		try {
			int num_user = 1;
			Calendar calendar = Calendar.getInstance();
			boolean trace_flag = false;

			CloudSim.init(num_user, calendar, trace_flag);
			CloudSim.terminateSimulation(simulationTime);

			String appId = cryptoScheme + "_auth";

			FogBroker broker = new FogBroker("broker");

			Application application = createApplication(appId, broker.getId());
			application.setUserId(broker.getId());

			createFogDevices(broker.getId(), appId);

			ModuleMapping moduleMapping = ModuleMapping.createModuleMapping();

			if (placementMode.equals("cloud")) {
				// Cloud-only baseline: ALL modules on cloud, IoT/Edge/Relay are just forwarders
				// This simulates a flat cloud architecture where PQC signatures traverse the full WAN
				for (FogDevice device : fogDevices) {
					if (device.getName().startsWith("cloud")) {
						moduleMapping.addModuleToDevice("crypto_signer", device.getName());
						moduleMapping.addModuleToDevice("sig_verifier", device.getName());
						moduleMapping.addModuleToDevice("did_resolver", device.getName());
						moduleMapping.addModuleToDevice("onchain_verifier", device.getName());
						moduleMapping.addModuleToDevice("auth_decision", device.getName());
					}
				}
			} else {
				// Fog (Edgewards): distribute modules across tiers
				for (FogDevice device : fogDevices) {
					if (device.getName().startsWith("m-")) {
						moduleMapping.addModuleToDevice("crypto_signer", device.getName());
					}
					if (device.getName().startsWith("d-")) {
						moduleMapping.addModuleToDevice("sig_verifier", device.getName());
					}
					if (device.getName().startsWith("proxy-server")) {
						moduleMapping.addModuleToDevice("did_resolver", device.getName());
					}
					if (device.getName().startsWith("cloud")) {
						moduleMapping.addModuleToDevice("onchain_verifier", device.getName());
						moduleMapping.addModuleToDevice("auth_decision", device.getName());
					}
				}
			}

			Controller controller = new Controller("master-controller", fogDevices, sensors,
					actuators);

			controller.submitApplication(application, 0,
					new ModulePlacementEdgewards(fogDevices, sensors, actuators, application, moduleMapping));

			TimeKeeper.getInstance().setSimulationStartTime(Calendar.getInstance().getTimeInMillis());

			CloudSim.startSimulation();
			CloudSim.stopSimulation();

			printSimulationResults();

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("SIMULATION_ERROR: " + e.getMessage());
		}
	}

	private static void createFogDevices(int userId, String appId) {
		FogDevice cloud = createFogDevice("cloud", CLOUD_MIPS, CLOUD_RAM, CLOUD_UP_BW, CLOUD_DOWN_BW,
			0, 0.01, CLOUD_BUSY_W, CLOUD_IDLE_W);
		cloud.setParentId(-1);
		fogDevices.add(cloud);

		// Single actuator on cloud for loop completion (avoids DOWN broadcast)
		Actuator actuator = new Actuator("actuator", userId, appId, "AUTH_RESULT");
		actuator.setGatewayDeviceId(cloud.getId());
		actuator.setLatency(0);
		actuators.add(actuator);

		for (int i = 0; i < numOfRelays; i++) {
			FogDevice relay = createFogDevice("proxy-server_" + i, RELAY_MIPS, RELAY_RAM, RELAY_UP_BW, RELAY_DOWN_BW,
				1, 0.01, RELAY_BUSY_W, RELAY_IDLE_W);
			relay.setParentId(cloud.getId());
			relay.setUplinkLatency(RELAY_UPLINK_LATENCY);
			fogDevices.add(relay);

			int gatewaysPerRelay = numOfEdgeGateways / numOfRelays;
			for (int j = 0; j < gatewaysPerRelay; j++) {
				int gwId = i * gatewaysPerRelay + j;
				FogDevice edgeGateway = createFogDevice("d-" + gwId, EDGE_MIPS, EDGE_RAM, EDGE_UP_BW, EDGE_DOWN_BW,
					2, 0.01, EDGE_BUSY_W, EDGE_IDLE_W);
				edgeGateway.setParentId(relay.getId());
				edgeGateway.setUplinkLatency(EDGE_UPLINK_LATENCY);
				fogDevices.add(edgeGateway);

				int iotPerGateway = numOfIoTDevices / numOfEdgeGateways;
				for (int k = 0; k < iotPerGateway; k++) {
					String iotName = "m-" + gwId + "-" + k;
					FogDevice iotDevice = createFogDevice(iotName, IOT_MIPS, IOT_RAM, IOT_UP_BW, IOT_DOWN_BW,
						3, 0, IOT_BUSY_W, IOT_IDLE_W);
					iotDevice.setParentId(edgeGateway.getId());
					iotDevice.setUplinkLatency(IOT_UPLINK_LATENCY);
					fogDevices.add(iotDevice);

					Sensor sensor = new Sensor("sensor_" + gwId + "_" + k, "SENSOR", userId, appId,
						new UniformDistribution(48.0, 60.0));
					sensor.setGatewayDeviceId(iotDevice.getId());
					sensor.setLatency(SENSOR_NET_LATENCY);
					sensors.add(sensor);
				}
			}
		}
	}

	private static FogDevice createFogDevice(String nodeName, long mips,
			int ram, long upBw, long downBw, int level, double ratePerMips, double busyPower, double idlePower) {

		List<Pe> peList = new ArrayList<Pe>();
		peList.add(new Pe(0, new PeProvisionerOverbooking(mips)));

		int hostId = FogUtils.generateEntityId();
		long storage = 1000000;
		int bw = 10000;

		PowerHost host = new PowerHost(
				hostId,
				new RamProvisionerSimple(ram),
				new BwProvisionerOverbooking(bw),
				storage,
				peList,
				new StreamOperatorScheduler(peList),
				new FogLinearPowerModel(busyPower, idlePower)
			);

		List<Host> hostList = new ArrayList<Host>();
		hostList.add(host);

		FogDeviceCharacteristics characteristics = new FogDeviceCharacteristics(
				"x86", "Linux", "Xen", host, 10.0, 3.0, 0.05, 0.001, 0.0);

		FogDevice fogdevice = null;
		try {
			fogdevice = new FogDevice(nodeName, characteristics,
					new AppModuleAllocationPolicy(hostList), new LinkedList<Storage>(),
					10, upBw, downBw, 0, ratePerMips);
		} catch (Exception e) {
			e.printStackTrace();
		}

		fogdevice.setLevel(level);
		return fogdevice;
	}

	@SuppressWarnings("serial")
	private static Application createApplication(String appId, int userId) {

		Application application = Application.createApplication(appId, userId);

		double signMI, verifyMI, tupleSize;
		if (cryptoScheme.equals("ecdsa")) {
			signMI = ECDSA_SIGN_MI;
			verifyMI = ECDSA_VERIFY_MI;
			tupleSize = SENSOR_DATA_SIZE + ECDSA_SIG_SIZE + ECDSA_PK_SIZE;
		} else if (cryptoScheme.equals("dilithium2")) {
			signMI = DILITHIUM2_SIGN_MI;
			verifyMI = DILITHIUM2_VERIFY_MI;
			tupleSize = SENSOR_DATA_SIZE + DILITHIUM2_SIG_SIZE + DILITHIUM2_PK_SIZE;
		} else { // falcon (default)
			signMI = FALCON_SIGN_MI;
			verifyMI = FALCON_VERIFY_MI;
			tupleSize = SENSOR_DATA_SIZE + FALCON_SIG_SIZE + FALCON_PK_SIZE;
		}
		double responseSize = 200;

		// Modules
		application.addAppModule("crypto_signer", 10);
		application.addAppModule("sig_verifier", 50);
		application.addAppModule("did_resolver", 50);
		application.addAppModule("onchain_verifier", 100);
		application.addAppModule("auth_decision", 30);

		// All-UP pipeline (no DOWN edges to avoid iFogSim broadcast amplification)
		// Edge MI = cost on DESTINATION module's device:
		//   SENSOR edge → crypto_signer (IoT):  signMI   → signMI/100 MIPS
		//   SIGNED_DATA edge → sig_verifier (Edge): verifyMI → verifyMI/6000 MIPS
		//   VERIFY_REQUEST edge → did_resolver (Relay): DID_RESOLVE_MI → 200/4000 MIPS
		//   DID_RESOLVED edge → onchain_verifier (Cloud): BLOCKCHAIN_VERIFY_MI → 2000/20000 MIPS
		application.addAppEdge("SENSOR", "crypto_signer", signMI, SENSOR_DATA_SIZE,
			"SENSOR", Tuple.UP, AppEdge.SENSOR);
		application.addAppEdge("crypto_signer", "sig_verifier", verifyMI,
			tupleSize, "SIGNED_DATA", Tuple.UP, AppEdge.MODULE);
		application.addAppEdge("sig_verifier", "did_resolver", DID_RESOLVE_MI,
			tupleSize, "VERIFY_REQUEST", Tuple.UP, AppEdge.MODULE);
		application.addAppEdge("did_resolver", "onchain_verifier", BLOCKCHAIN_VERIFY_MI,
			tupleSize, "DID_RESOLVED", Tuple.UP, AppEdge.MODULE);
		application.addAppEdge("onchain_verifier", "auth_decision", 50,
			responseSize, "CHAIN_RESULT", Tuple.UP, AppEdge.MODULE);
		application.addAppEdge("auth_decision", "AUTH_RESULT", 50, responseSize,
			"AUTH_RESULT", Tuple.UP, AppEdge.ACTUATOR);

		// Tuple mappings (all 1:1)
		application.addTupleMapping("crypto_signer", "SENSOR", "SIGNED_DATA",
			new FractionalSelectivity(1.0));
		application.addTupleMapping("sig_verifier", "SIGNED_DATA", "VERIFY_REQUEST",
			new FractionalSelectivity(1.0));
		application.addTupleMapping("did_resolver", "VERIFY_REQUEST", "DID_RESOLVED",
			new FractionalSelectivity(1.0));
		application.addTupleMapping("onchain_verifier", "DID_RESOLVED", "CHAIN_RESULT",
			new FractionalSelectivity(1.0));
		application.addTupleMapping("auth_decision", "CHAIN_RESULT", "AUTH_RESULT",
			new FractionalSelectivity(1.0));

		// E2E loop definition
		final AppLoop loop = new AppLoop(new ArrayList<String>() {{
			add("SENSOR");
			add("crypto_signer");
			add("sig_verifier");
			add("did_resolver");
			add("onchain_verifier");
			add("auth_decision");
			add("AUTH_RESULT");
		}});
		List<AppLoop> loops = new ArrayList<AppLoop>() {{ add(loop); }};
		application.setLoops(loops);

		return application;
	}

	private static void printSimulationResults() {
		double iotEnergy = 0, edgeEnergy = 0, relayEnergy = 0, cloudEnergy = 0;
		int iotCount = 0, edgeCount = 0, relayCount = 0;
		for (FogDevice device : fogDevices) {
			double energy = device.getEnergyConsumption();
			if (device.getName().startsWith("m-")) { iotEnergy += energy; iotCount++; }
			else if (device.getName().startsWith("d-")) { edgeEnergy += energy; edgeCount++; }
			else if (device.getName().startsWith("proxy-server")) { relayEnergy += energy; relayCount++; }
			else if (device.getName().startsWith("cloud")) { cloudEnergy += energy; }
		}
		double totalEnergy = iotEnergy + edgeEnergy + relayEnergy + cloudEnergy;

		Map<String, Double> cpuTimes = TimeKeeper.getInstance().getTupleTypeToAverageCpuTime();
		Map<Integer, Double> loopDelays = TimeKeeper.getInstance().getLoopIdToCurrentAverage();

		// Get scheme-specific info
		double signMI, verifyMI, sigBytes, pkBytes;
		if (cryptoScheme.equals("ecdsa")) {
			signMI = ECDSA_SIGN_MI; verifyMI = ECDSA_VERIFY_MI;
			sigBytes = ECDSA_SIG_SIZE; pkBytes = ECDSA_PK_SIZE;
		} else if (cryptoScheme.equals("dilithium2")) {
			signMI = DILITHIUM2_SIGN_MI; verifyMI = DILITHIUM2_VERIFY_MI;
			sigBytes = DILITHIUM2_SIG_SIZE; pkBytes = DILITHIUM2_PK_SIZE;
		} else {
			signMI = FALCON_SIGN_MI; verifyMI = FALCON_VERIFY_MI;
			sigBytes = FALCON_SIG_SIZE; pkBytes = FALCON_PK_SIZE;
		}
		double tupleBytes = SENSOR_DATA_SIZE + sigBytes + pkBytes;

		// Estimated processing times on each device tier (ms)
		double iotSignMs = signMI / IOT_MIPS;
		double edgeVerifyMs = verifyMI / EDGE_MIPS;
		double relayDidMs = DID_RESOLVE_MI / RELAY_MIPS;
		double cloudVerifyMs = BLOCKCHAIN_VERIFY_MI / CLOUD_MIPS;

		// Network latency (per-hop, doubled for round-trip modeling)
		double netLatencyTotal = SENSOR_NET_LATENCY + IOT_UPLINK_LATENCY +
			EDGE_UPLINK_LATENCY + RELAY_UPLINK_LATENCY;  // 164ms round-trip

		// Bandwidth transmission delay per hop (seconds = bytes / Bps, convert to ms)
		double sensorBwDelayMs = (SENSOR_DATA_SIZE / (double)ANALYTICAL_IOT_BW) * 1000;
		double iotEdgeBwDelayMs = (tupleBytes / (double)ANALYTICAL_IOT_BW) * 1000;
		double edgeRelayBwDelayMs = (tupleBytes / (double)ANALYTICAL_EDGE_BW) * 1000;
		double relayCloudBwDelayMs = (tupleBytes / (double)ANALYTICAL_RELAY_BW) * 1000;
		double totalBwDelayMs = sensorBwDelayMs + iotEdgeBwDelayMs + edgeRelayBwDelayMs + relayCloudBwDelayMs;

		// Actual data transmitted (formula-based, not NetworkUsageMonitor)
		// Each tuple chain: 4 inter-device hops with known sizes
		// sensor->IoT: SENSOR_DATA_SIZE, IoT->Edge/Relay->Cloud: tupleBytes
		// Plus within-cloud: responseSize x 2 (CHAIN_RESULT + AUTH_RESULT)
		double responseSize = 200;
		double dataPerChain = SENSOR_DATA_SIZE + tupleBytes * 3 + responseSize * 2;
		double meanTuplesPerDevice = simulationTime / 54.0; // Uniform(48,60) has mean 54
		double totalNetworkDataBytes = numOfIoTDevices * meanTuplesPerDevice * dataPerChain;
		double totalNetworkDataGB = totalNetworkDataBytes / (1024.0 * 1024.0 * 1024.0);

		// ---- JSON output ----
		System.out.println("\n=== RESULTS_JSON_START ===");
		System.out.println("{");
		System.out.println("  \"scheme\": \"" + cryptoScheme + "\",");
		System.out.println("  \"placement\": \"" + placementMode + "\",");
		System.out.println("  \"num_iot\": " + numOfIoTDevices + ",");
		System.out.println("  \"num_gateways\": " + numOfEdgeGateways + ",");
		System.out.println("  \"num_relays\": " + numOfRelays + ",");
		System.out.println("  \"sim_time_s\": " + simulationTime + ",");

		System.out.println("  \"energy\": {");
		System.out.println("    \"iot_total_Ws\": " + String.format("%.2f", iotEnergy) + ",");
		System.out.println("    \"iot_avg_Ws\": " + String.format("%.4f", (iotCount > 0 ? iotEnergy/iotCount : 0)) + ",");
		System.out.println("    \"edge_total_Ws\": " + String.format("%.2f", edgeEnergy) + ",");
		System.out.println("    \"edge_avg_Ws\": " + String.format("%.2f", (edgeCount > 0 ? edgeEnergy/edgeCount : 0)) + ",");
		System.out.println("    \"relay_total_Ws\": " + String.format("%.2f", relayEnergy) + ",");
		System.out.println("    \"cloud_Ws\": " + String.format("%.2f", cloudEnergy) + ",");
		System.out.println("    \"total_Ws\": " + String.format("%.2f", totalEnergy));
		System.out.println("  },");

		System.out.println("  \"cpu_time_ms\": {");
		if (cpuTimes != null && !cpuTimes.isEmpty()) {
			int i = 0;
			for (Map.Entry<String, Double> entry : cpuTimes.entrySet()) {
				String comma = (i < cpuTimes.size() - 1) ? "," : "";
				System.out.println("    \"" + entry.getKey() + "\": " +
					String.format("%.4f", entry.getValue()) + comma);
				i++;
			}
		}
		System.out.println("  },");

		System.out.println("  \"loop_latency\": {");
		if (loopDelays != null && !loopDelays.isEmpty()) {
			int i = 0;
			for (Map.Entry<Integer, Double> entry : loopDelays.entrySet()) {
				String comma = (i < loopDelays.size() - 1) ? "," : "";
				System.out.println("    \"loop_" + entry.getKey() + "\": " +
					String.format("%.4f", entry.getValue()) + comma);
				i++;
			}
		}
		System.out.println("  },");

		// Corrected: actual data volume, not latency*size product
		System.out.println("  \"network_data_GB\": " + String.format("%.4f", totalNetworkDataGB) + ",");

		// Per-hop latency breakdown
		System.out.println("  \"latency_breakdown_ms\": {");
		System.out.println("    \"iot_sign\": " + String.format("%.4f", iotSignMs) + ",");
		System.out.println("    \"edge_verify\": " + String.format("%.4f", edgeVerifyMs) + ",");
		System.out.println("    \"relay_did_resolve\": " + String.format("%.4f", relayDidMs) + ",");
		System.out.println("    \"cloud_onchain_verify\": " + String.format("%.4f", cloudVerifyMs) + ",");
		System.out.println("    \"network_roundtrip\": " + String.format("%.1f", netLatencyTotal) + ",");
		System.out.println("    \"total_compute\": " + String.format("%.4f", iotSignMs + edgeVerifyMs + relayDidMs + cloudVerifyMs) + ",");
		System.out.println("    \"compute_plus_network\": " + String.format("%.1f", iotSignMs + edgeVerifyMs + relayDidMs + cloudVerifyMs + netLatencyTotal));
		System.out.println("  },");

		// Bandwidth delay breakdown (from iFogSim's fileSize/bandwidth model)
		System.out.println("  \"bw_delay_ms\": {");
		System.out.println("    \"sensor_to_iot\": " + String.format("%.4f", sensorBwDelayMs) + ",");
		System.out.println("    \"iot_to_edge\": " + String.format("%.4f", iotEdgeBwDelayMs) + ",");
		System.out.println("    \"edge_to_relay\": " + String.format("%.4f", edgeRelayBwDelayMs) + ",");
		System.out.println("    \"relay_to_cloud\": " + String.format("%.4f", relayCloudBwDelayMs) + ",");
		System.out.println("    \"total_bw_delay\": " + String.format("%.4f", totalBwDelayMs));
		System.out.println("  },");

		System.out.println("  \"per_tx_estimate\": {");
		System.out.println("    \"sign_MI\": " + String.format("%.0f", signMI) + ",");
		System.out.println("    \"verify_MI\": " + String.format("%.0f", verifyMI) + ",");
		System.out.println("    \"did_resolve_MI\": " + String.format("%.0f", DID_RESOLVE_MI) + ",");
		System.out.println("    \"onchain_verify_MI\": " + String.format("%.0f", BLOCKCHAIN_VERIFY_MI) + ",");
		System.out.println("    \"tuple_size_bytes\": " + String.format("%.0f", tupleBytes) + ",");
		System.out.println("    \"pk_size_bytes\": " + String.format("%.0f", pkBytes) + ",");
		System.out.println("    \"sig_size_bytes\": " + String.format("%.0f", sigBytes));
		System.out.println("  }");

		System.out.println("}");
		System.out.println("=== RESULTS_JSON_END ===");

		// Human-readable summary
		System.out.println("\n=== SUMMARY ===");
		System.out.println("Scheme: " + cryptoScheme.toUpperCase() + " | Devices: " + numOfIoTDevices +
			" | Gateways: " + numOfEdgeGateways + " | Relays: " + numOfRelays);
		System.out.println("Total Energy: " + String.format("%.2f", totalEnergy) + " W-s");
		System.out.println("  L1-IoT (" + iotCount + "): " + String.format("%.2f", iotEnergy) + " W-s total, " +
			String.format("%.4f", (iotCount > 0 ? iotEnergy/iotCount : 0)) + " W-s avg");
		System.out.println("  L2-Edge (" + edgeCount + "): " + String.format("%.2f", edgeEnergy) + " W-s total, " +
			String.format("%.2f", (edgeCount > 0 ? edgeEnergy/edgeCount : 0)) + " W-s avg");
		System.out.println("  L3-Relay (" + relayCount + "): " + String.format("%.2f", relayEnergy) + " W-s");
		System.out.println("  L4-Cloud: " + String.format("%.2f", cloudEnergy) + " W-s");
		System.out.println("Network Data (actual): " + String.format("%.4f", totalNetworkDataGB) + " GB");
		System.out.println("Per-hop compute (ms): IoT_sign=" + String.format("%.3f", iotSignMs) +
			" Edge_verify=" + String.format("%.4f", edgeVerifyMs) +
			" Relay_DID=" + String.format("%.4f", relayDidMs) +
			" Cloud_BC=" + String.format("%.4f", cloudVerifyMs));
		System.out.println("Network latency (round-trip): " + String.format("%.1f", netLatencyTotal) + "ms");
		System.out.println("BW delay per hop (ms): sensor->IoT=" + String.format("%.3f", sensorBwDelayMs) +
			" IoT->Edge=" + String.format("%.3f", iotEdgeBwDelayMs) +
			" Edge->Relay=" + String.format("%.3f", edgeRelayBwDelayMs) +
			" Relay->Cloud=" + String.format("%.3f", relayCloudBwDelayMs) +
			" total=" + String.format("%.3f", totalBwDelayMs));

		if (loopDelays != null && !loopDelays.isEmpty()) {
			for (Map.Entry<Integer, Double> entry : loopDelays.entrySet()) {
				System.out.println("E2E Loop Latency: " + String.format("%.4f", entry.getValue()) + " ms");
			}
		}
		if (cpuTimes != null && !cpuTimes.isEmpty()) {
			System.out.println("CPU Time per Tuple:");
			for (Map.Entry<String, Double> entry : cpuTimes.entrySet()) {
				System.out.println("  " + entry.getKey() + ": " +
					String.format("%.4f", entry.getValue()) + " ms");
			}
		}
	}
}
