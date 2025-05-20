<script lang="ts">
	import Pagination from '$lib/components/common/Pagination.svelte';
	import { getContext, onMount } from 'svelte';
	import { listAllCreditLog } from '$lib/apis/credit';
	import { toast } from 'svelte-sonner';

	const i18n = getContext('i18n');

	let page = 1;
	let limit = 10;
	let total = 0;

	$: if (page) {
		doQuery();
	}

	let userID = '';

	$: if (userID !== undefined) {
		page = 1;
		doQuery();
	}

	let logs = [];
	const doQuery = async () => {
		const data = await listAllCreditLog(localStorage.token, page, limit, userID).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (data) {
			total = data?.total ?? 0;
			logs = data?.results ?? [];
		}
	};

	const formatDate = (t: number): string => {
		return new Date(t * 1000).toLocaleString();
	};

	const formatDesc = (log: Log): string => {
		const usage = log?.detail?.usage ?? {};
		if (usage && Object.keys(usage).length > 0) {
			if (usage.total_price !== undefined && usage.total_price !== null) {
				return `-${Math.round(usage.total_price * 1e6) / 1e6}`;
			}
			if (usage.request_unit_price) {
				return `-${usage.request_unit_price / 1e6}`;
			}
			if (usage.prompt_unit_price || usage.completion_unit_price) {
				return `-${Math.round(usage.prompt_tokens * usage.prompt_unit_price + usage.completion_tokens * usage.completion_unit_price) / 1e6}`;
			}
		}
		return log?.detail?.desc;
	};

	onMount(async () => {
		await doQuery();
	});
</script>

<div class="mt-0.5 mb-2 gap-1 flex flex-col md:flex-row justify-between">
	<div class="flex md:self-center text-lg font-medium px-0.5">
		<div class="flex-shrink-0">
			{$i18n.t('Credit Log')}
		</div>
	</div>

	<div class="flex gap-1">
		<div class=" flex w-full space-x-2">
			<div class="flex flex-1 w-full">
				<div class=" self-center ml-1 mr-3">
					<svg
						xmlns="http://www.w3.org/2000/svg"
						viewBox="0 0 20 20"
						fill="currentColor"
						class="w-4 h-4"
					>
						<path
							fill-rule="evenodd"
							d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z"
							clip-rule="evenodd"
						/>
					</svg>
				</div>
				<input
					class=" w-full text-sm pr-4 py-1 rounded-r-xl outline-hidden bg-transparent"
					bind:value={userID}
					placeholder={$i18n.t('Search User ID')}
				/>
			</div>
		</div>
	</div>
</div>
<div class="mt-2 scrollbar-hidden relative whitespace-nowrap overflow-x-auto max-w-full rounded-sm">
	<table
		class="w-full text-sm text-left text-gray-500 dark:text-gray-400 table-auto max-w-full rounded-sm}"
	>
		<thead
			class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-850 dark:text-gray-400 -translate-y-0.5"
		>
			<tr>
				<th scope="col" class="px-3 py-1.5 select-none w-3">
					{$i18n.t('Date')}
				</th>
				<th scope="col" class="px-3 py-1.5 select-none w-3">
					{$i18n.t('User (User ID)')}
				</th>
				<th scope="col" class="px-3 py-1.5 select-none w-3">
					{$i18n.t('Credit')}
				</th>
				<th scope="col" class="px-3 py-1.5 select-none w-3">
					{$i18n.t('Model')}
				</th>
				<th scope="col" class="px-3 py-1.5 select-none w-3">
					{$i18n.t('Desc')}
				</th>
			</tr>
		</thead>
		<tbody>
			{#each logs as log}
				<tr class="bg-white dark:bg-gray-900 dark:border-gray-850 text-xs group">
					<td class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit">
						<div class=" line-clamp-1">
							{formatDate(log.created_at)}
						</div>
					</td>
					<td class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit">
						<div class=" line-clamp-1">
							{log.username || '- -'} ({log.user_id})
						</div>
					</td>
					<td class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit">
						<div class=" line-clamp-1">
							{parseFloat(log.credit).toFixed(6)}
						</div>
					</td>
					<td class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit">
						<div class=" line-clamp-1">
							{log.detail?.api_params?.model?.name || log.detail?.api_params?.model?.id || '- -'}
						</div>
					</td>
					<td class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit">
						<div class=" line-clamp-1">
							{formatDesc(log)}
						</div>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>

<Pagination bind:page count={total} perPage={limit} />
