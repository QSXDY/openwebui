<script lang="ts">
	import { marked } from 'marked';

	import { onMount, getContext } from 'svelte';
	const i18n = getContext('i18n');

	import { WEBUI_NAME, config, models as _models, settings, models } from '$lib/stores';

	import { getModels } from '$lib/apis';
	import { getGroups } from '$lib/apis/groups';
	import Tooltip from '../common/Tooltip.svelte';
	import Search from '../icons/Search.svelte';
	import ChevronRight from '../icons/ChevronRight.svelte';
	import Spinner from '../common/Spinner.svelte';
	let loaded = false;
	let tagsContainerElement;

	let selectedTag = '';
	let selectedConnectionType = '';
	let modelslist = [];
	let tags = [];
	let searchValue = '';

	$: {
		const lisda = $models.filter((item) => {
			if (selectedTag === '') {
				return true;
			}
			return (item.tags ?? []).map((tag) => tag.name).includes(selectedTag);
		});
		modelslist = lisda;

		// 在这里可以添加当 selectedTag 变化时需要执行的逻辑
	}

	onMount(async () => {
		modelslist = $models;
		if (modelslist) {
			tags = modelslist
				.filter((item) => !(item.info?.meta?.hidden ?? false))
				.flatMap((item) => item.tags ?? [])
				.map((tag) => tag.name);

			// Remove duplicates and sort
			tags = Array.from(new Set(tags)).sort((a, b) => a.localeCompare(b));
			// console.log('modelstagstagstagslist',modelslist, tags);
		}

		loaded = true;
	});
</script>

<svelte:head>
	<title>
		{$i18n.t('Models')} • {$WEBUI_NAME}
	</title>
</svelte:head>

{#if loaded}
	<div class="flex flex-col gap-1 my-1.5">
		<div class="flex justify-between items-center">
			{#if tags && modelslist.filter((item) => !(item.info?.meta?.hidden ?? false)).length > 0}
				<div
					class=" flex w-full sticky top-0 z-10 bg-white dark:bg-gray-850 overflow-x-auto scrollbar-none"
					on:wheel={(e) => {
						if (e.deltaY !== 0) {
							e.preventDefault();
							e.currentTarget.scrollLeft += e.deltaY;
						}
					}}
				>
					<div
						class="flex gap-1 w-fit text-center text-sm font-medium rounded-full bg-transparent px-1.5 pb-0.5"
						bind:this={tagsContainerElement}
					>
						{#if (modelslist.find((item) => item.model?.owned_by === 'ollama') && modelslist.find((item) => item.model?.owned_by === 'openai')) || modelslist.find((item) => item.model?.direct) || tags.length > 0}
							<button
								class="min-w-fit outline-none p-1.5 {selectedTag === '' &&
								selectedConnectionType === ''
									? ''
									: 'text-gray-300 dark:text-gray-600 hover:text-gray-700 dark:hover:text-white'} transition capitalize"
								on:click={() => {
									selectedConnectionType = '';
									selectedTag = '';
								}}
							>
								{$i18n.t('All')}
							</button>
						{/if}

						{#each tags as tag}
							<button
								class="min-w-fit outline-none p-1.5 {selectedTag === tag
									? ''
									: 'text-gray-300 dark:text-gray-600 hover:text-gray-700 dark:hover:text-white'} transition capitalize"
								on:click={() => {
									selectedConnectionType = '';
									selectedTag = tag;
								}}
							>
								{tag}
							</button>
						{/each}
					</div>
				</div>
			{/if}
		</div>

		<div class=" flex flex-1 items-center w-full space-x-2">
			<div class="flex flex-1 items-center">
				<div class=" self-center ml-1 mr-3">
					<Search className="size-3.5" />
				</div>
				<input
					class=" w-full text-sm py-1 rounded-r-xl outline-hidden bg-transparent"
					bind:value={searchValue}
					placeholder={$i18n.t('Search Models')}
				/>
			</div>
		</div>
	</div>

	<div class=" my-2 mb-5 gap-2 grid lg:grid-cols-2 xl:grid-cols-3" id="model-list">
		{#each modelslist as model}
			<div
				class=" flex flex-col cursor-pointer w-full px-3 py-2 dark:hover:bg-white/5 hover:bg-black/5 rounded-xl transition"
				id="model-item-{model.id}"
			>
				<div class="flex gap-4 mt-0.5 mb-0.5">
					<div class=" w-[44px]">
						<div class=" rounded-full object-cover {model.is_active ? '' : ''} ">
							<img
								src={model?.info?.meta?.profile_image_url ?? '/static/favicon.png'}
								alt="modelfile profile"
								class=" rounded-full w-full h-auto object-cover"
							/>
						</div>
					</div>

					<a
						class=" flex flex-1 cursor-pointer w-full"
						href={`/?models=${encodeURIComponent(model.id)}`}
					>
						<div class=" flex-1 self-center {model.is_active ? '' : 'text-gray'}">
							<Tooltip
								content={marked.parse(model?.info?.meta?.description ?? model.id)}
								className=" w-fit"
								placement="top-start"
							>
								<div class=" font-semibold line-clamp-1">{model.name}</div>
							</Tooltip>

							<div class="flex gap-1 text-xs overflow-hidden">
								<div class="line-clamp-3">
									{#if (model?.info?.meta?.description ?? '').trim()}
										{model?.info?.meta?.description}
									{:else}
										{model.id}
									{/if}
								</div>
							</div>
						</div>
					</a>
				</div>
				<div class="w-full flex items-center justify-end gap-1">
					{#if model?.tags?.length > 0}
						<div
							class="flex gap-0.5 self-center items-center h-full translate-y-[0.5px] overflow-x-auto scrollbar-none"
						>
							{#each model.tags as tag}
								<Tooltip content={tag.name} className="flex-shrink-0">
									<div
										class="text-xs font-bold px-1 rounded-sm uppercase bg-gray-500/20 text-gray-700 dark:text-gray-200"
									>
										{tag.name}
									</div>
								</Tooltip>
							{/each}
						</div>
					{/if}
				</div>
				<!-- <div class="flex justify-between items-center -mb-0.5 px-0.5">
					<div class=" text-xs mt-0.5">
						<Tooltip
							content={model?.user?.email ?? $i18n.t('Deleted User')}
							className="flex shrink-0"
							placement="top-start"
						>
							<div class="shrink-0 text-gray">
								{$i18n.t('By {{name}}', {
									name: capitalizeFirstLetter(
										model?.user?.name ?? model?.user?.email ?? $i18n.t('Deleted User')
									)
								})}
							</div>
						</Tooltip>
					</div>

				</div> -->
			</div>
		{/each}
	</div>

	{#if $config?.features.enable_community_sharing}
		{#if false}
			<div class=" my-16">
				<div class=" text-xl font-medium mb-1 line-clamp-1">
					{$i18n.t('Made by Open WebUI Community')}
				</div>

				<a
					class=" flex cursor-pointer items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-850 w-full mb-2 px-3.5 py-1.5 rounded-xl transition"
					href="https://openwebui.com/#open-webui-community"
					target="_blank"
				>
					<div class=" self-center">
						<div class=" font-semibold line-clamp-1">{$i18n.t('Discover a model')}</div>
						<div class=" text-sm line-clamp-1">
							{$i18n.t('Discover, download, and explore model presets')}
						</div>
					</div>

					<div>
						<div>
							<ChevronRight />
						</div>
					</div>
				</a>
			</div>
		{/if}
	{/if}
{:else}
	<div class="w-full h-full flex justify-center items-center">
		<Spinner />
	</div>
{/if}
