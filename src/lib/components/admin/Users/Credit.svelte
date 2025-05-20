<script lang="ts">
	import { getContext, onMount } from 'svelte';
	import { getCreditStats } from '$lib/apis/credit';
	import { toast } from 'svelte-sonner';
	import * as echarts from 'echarts';
	import type { EChartsType } from 'echarts';
	import { theme } from '$lib/stores';

	const maxDimensions = 15;
	const echartsTheme = $theme.includes('dark') ? 'dark' : 'light';

	let userPaymentLine: HTMLDivElement;
	let userPaymentLineOption = {};
	let userPaymentLineChart: EChartsType;

	let modelTokenPie: HTMLDivElement;
	let modelTokenPieOption = {};
	let modelTokenPieChart: EChartsType;

	let modelCostPie: HTMLDivElement;
	let modelCostPieOption = {};
	let modelCostPieChart: EChartsType;

	let userTokenPie: HTMLDivElement;
	let userTokenPieOption = {};
	let userTokenPieChart: EChartsType;

	let userCostPie: HTMLDivElement;
	let userCostPieOption = {};
	let userCostPieChart: EChartsType;

	const i18n = getContext('i18n');

	type ChartItem = {
		name: string;
		value: number;
	};
	type Data = {
		model_cost_pie: Array<ChartItem>;
		model_token_pie: Array<ChartItem>;
		user_cost_pie: Array<ChartItem>;
		user_token_pie: Array<ChartItem>;
		user_payment_stats_x: Array<String>;
		user_payment_stats_y: Array<Number>;
	};

	let period = 7;

	let endTime = new Date();
	let startTime = new Date();

	const onChangePeriod = async (p: number) => {
		period = p;
		await doQuery();
	};

	const mergeData = (data: Array<ChartItem>) => {
		let sorted = data.sort((a, b) => b.value - a.value);
		let topItems = sorted.slice(0, maxDimensions);
		let rest = sorted.slice(maxDimensions);
		let restSum = rest.reduce((sum, item) => sum + item.value, 0);
		return [...topItems, ...(restSum > 0 ? [{ name: $i18n.t('Other'), value: restSum }] : [])];
	};

	const doQuery = async () => {
		endTime = new Date();
		startTime = new Date();
		startTime.setDate(endTime.getDate() - period);

		const data = await getCreditStats(localStorage.token, {
			start_time: Math.round(startTime.getTime() / 1000),
			end_time: Math.round(endTime.getTime() / 1000)
		}).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (data) {
			drawChart(data);
		}
	};

	const drawChart = (data: Data) => {
		if (!userPaymentLineChart) {
			userPaymentLineChart = echarts.init(userPaymentLine, echartsTheme);
		}
		userPaymentLineOption = {
			title: {
				text: $i18n.t('User Payment Stats'),
				textStyle: {
					fontSize: 14,
					fontWeight: '400'
				}
			},
			legend: {
				type: 'scroll',
				bottom: '10px',
				left: '10px',
				right: '10px'
			},
			tooltip: {
				show: true,
				trigger: 'axis'
			},
			xAxis: {
				type: 'category',
				data: data.user_payment_stats_x
			},
			yAxis: {
				type: 'value'
			},
			series: [
				{
					data: data.user_payment_stats_y,
					type: 'line',
					areaStyle: {}
				}
			]
		};
		userPaymentLineChart.setOption(userPaymentLineOption);

		if (!modelTokenPieChart) {
			modelTokenPieChart = echarts.init(modelTokenPie, echartsTheme);
		}
		modelTokenPieOption = {
			title: {
				text: $i18n.t('Model Tokens Cost'),
				textStyle: {
					fontSize: 14,
					fontWeight: '400'
				}
			},
			legend: {
				type: 'scroll',
				bottom: '10px',
				left: '10px',
				right: '10px'
			},
			tooltip: {
				show: true
			},
			series: [
				{
					type: 'pie',
					data: mergeData(data.model_token_pie),
					radius: ['40%', '60%']
				}
			]
		};
		modelTokenPieChart.setOption(modelTokenPieOption);

		if (!modelCostPieChart) {
			modelCostPieChart = echarts.init(modelCostPie, echartsTheme);
		}
		modelCostPieOption = {
			title: {
				text: $i18n.t('Model Credit Cost'),
				textStyle: {
					fontSize: 14,
					fontWeight: '400'
				}
			},
			legend: {
				type: 'scroll',
				bottom: '10px',
				left: '10px',
				right: '10px'
			},
			tooltip: {
				show: true
			},
			series: [
				{
					type: 'pie',
					data: mergeData(data.model_cost_pie),
					radius: ['40%', '60%']
				}
			]
		};
		modelCostPieChart.setOption(modelCostPieOption);

		if (!userTokenPieChart) {
			userTokenPieChart = echarts.init(userTokenPie, echartsTheme);
		}
		userTokenPieOption = {
			title: {
				text: $i18n.t('User Tokens Cost'),
				textStyle: {
					fontSize: 14,
					fontWeight: '400'
				}
			},
			legend: {
				type: 'scroll',
				bottom: '10px',
				left: '10px',
				right: '10px'
			},
			tooltip: {
				show: true
			},
			series: [
				{
					type: 'pie',
					data: mergeData(data.user_token_pie),
					radius: ['40%', '60%']
				}
			]
		};
		userTokenPieChart.setOption(userTokenPieOption);

		if (!userCostPieChart) {
			userCostPieChart = echarts.init(userCostPie, echartsTheme);
		}
		userCostPieOption = {
			title: {
				text: $i18n.t('User Credit Cost'),
				textStyle: {
					fontSize: 14,
					fontWeight: '400'
				}
			},
			legend: {
				type: 'scroll',
				bottom: '10px',
				left: '10px',
				right: '10px'
			},
			tooltip: {
				show: true
			},
			series: [
				{
					type: 'pie',
					data: mergeData(data.user_cost_pie),
					radius: ['40%', '60%']
				}
			]
		};
		userCostPieChart.setOption(userCostPieOption);
	};

	onMount(async () => {
		await doQuery();
	});
</script>

<div class="mt-0.5 mb-2">
	<div class="flex md:self-center text-lg font-medium px-0.5">
		{$i18n.t('Credit Statistics')}
	</div>

	<div class="mt-2 flex justify-around h-[36px] white">
		<button
			class="w-full mr-2 rounded-md {period === 30
				? 'bg-gray-200 dark:text-stone-900 dark:bg-gray-750'
				: 'bg-gray-50 dark:text-gray-300 dark:bg-gray-850'}"
			on:click={async () => {
				await onChangePeriod(30);
			}}
		>
			{$i18n.t('Last 30 Days')}
		</button>
		<button
			class="w-full mr-2 rounded-md {period === 14
				? 'bg-gray-200 dark:text-stone-900 dark:bg-gray-750'
				: 'bg-gray-50 dark:text-gray-300 dark:bg-gray-850'}"
			on:click={async () => {
				await onChangePeriod(14);
			}}
		>
			{$i18n.t('Last 14 Days')}
		</button>
		<button
			class="w-full mr-2 rounded-md {period === 7
				? 'bg-gray-200 dark:text-stone-900 dark:bg-gray-750'
				: 'bg-gray-50 dark:text-gray-300 dark:bg-gray-850'}"
			on:click={async () => {
				await onChangePeriod(7);
			}}
		>
			{$i18n.t('Last 7 Days')}
		</button>
		<button
			class="w-full rounded-md {period === 1
				? 'bg-gray-200 dark:text-stone-900 dark:bg-gray-750'
				: 'bg-gray-50 dark:text-gray-300 dark:bg-gray-850'}"
			on:click={async () => {
				await onChangePeriod(1);
			}}
		>
			{$i18n.t('Today')}
		</button>
	</div>

	<div
		class="mt-2 bg-gray-50 rounded-md dark:text-gray-300 dark:bg-gray-850"
		bind:this={userPaymentLine}
		style="width: 100%; height: 300px;"
	></div>
	<div
		class="mt-2 bg-gray-50 rounded-md dark:text-gray-300 dark:bg-gray-850"
		bind:this={modelTokenPie}
		style="width: 100%; height: 300px;"
	></div>
	<div
		class="mt-2 bg-gray-50 rounded-md dark:text-gray-300 dark:bg-gray-850"
		bind:this={modelCostPie}
		style="width: 100%; height: 300px;"
	></div>
	<div
		class="mt-2 bg-gray-50 rounded-md dark:text-gray-300 dark:bg-gray-850"
		bind:this={userTokenPie}
		style="width: 100%; height: 300px;"
	></div>
	<div
		class="mt-2 bg-gray-50 rounded-md dark:text-gray-300 dark:bg-gray-850"
		bind:this={userCostPie}
		style="width: 100%; height: 300px;"
	></div>
</div>
