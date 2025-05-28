<script lang="ts">
	import { onMount } from 'svelte';
	import { getContext } from 'svelte';
	import { WEBUI_NAME, config, mobile, models as _models, settings, user } from '$lib/stores';
	import Personalapp from '$lib/components/workspace/Personalapp.svelte';
	import Publicapp from '$lib/components/workspace/Publicapp.svelte';
	// 类型定义（如果使用TypeScript）
	interface Tab {
		id: string;
		label: string;
	}

	// 定义标签页数据
	const TABS: Tab[] = [
		{ id: 'app-gallery', label: '应用广场' },
		{ id: 'my-apps', label: '我的应用' }
	];

	// 状态管理
	let activeTab: string = TABS[0].label; // 或者使用TABS[0].label作为默认值

	// 国际化上下文
	const i18n = getContext('i18n');

	// 生命周期钩子
	onMount(async () => {
		// 初始化逻辑（如果有）
	});

	// 切换标签页的方法
	function setActiveTab(tabLabel: string) {
		console.log(tabLabel);
		activeTab = tabLabel;
	}
</script>

<svelte:head>
	<title>{$i18n.t('Models')} • {$WEBUI_NAME}</title>
</svelte:head>

<div class="w-full flex flex-col h-full">
	<div class=" flex gap-2">
		{#each TABS as tab}
			<button
				on:click={() => setActiveTab(tab.label)}
				class:selected={activeTab == tab.label}
				class="min-w-fit rounded-full text-gray-300 dark:text-gray-600 hover:text-gray-700 dark:hover:text-white transition"
			>
				{tab.label}
			</button>
		{/each}
	</div>
	<div class="flex-1">
		{#if activeTab === '应用广场'}
			<Publicapp />
			<!-- 公开应用 -->
		{:else}
			<Personalapp />
			<!-- 我的应用 -->
		{/if}
	</div>
</div>

<style>
	.selected {
		color: #4e4e4e;
	}
	:global(.dark) .selected {
		color: white;
	}
</style>
