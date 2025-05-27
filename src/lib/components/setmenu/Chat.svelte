<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { goto } from '$app/navigation';
	import { onMount, getContext } from 'svelte';
	import { user } from '$lib/stores';
	import ConfirmDialog from '$lib/components/common/ExchangeDialog.svelte';
	import PaymentDialog from '$lib/components/common/PaymentDialog.svelte';
	import { getUsers, usersubscriptionmenu, subscriptionprocess } from '$lib/apis/setmenu';

	const i18n = getContext('i18n');

	let showDeleteConfirmDialog = false;
	let showPaymentDialog = false;
	let loaded = false;
	let menus: any[] = [];
	let frmoMenu = null;

	const usermenu = async () => {
		try {
			const res = await usersubscriptionmenu(localStorage.token, $user.id).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				// console.log('个人套餐', res);

				const unmatchedPlans = [res.subscription.plan];
				// 1. 将unmatchedPlans转换为Map，便于快速查找
				const planMap = new Map(unmatchedPlans.map((plan) => [plan.id, { ...plan, user_plan: 1 }]));

				// 2. 处理menus中的项：匹配的替换，未匹配的标记user_plan=0
				const matchedMenus = menus.map((menu) => {
					if (planMap.has(menu.plan_id)) {
						const matchedPlan = planMap.get(menu.plan_id);
						planMap.delete(menu.plan_id); // 删除已匹配的plan，避免重复添加
						return { ...matchedPlan, ...menu }; // 合并plan和menu字段
					}
					return { ...menu, user_plan: 0 }; // 未匹配的menu项
				});

				// 3. 处理未匹配的plan：添加到数组首位，标记user_plan=2
				const unmatchedPlansToPrepend = Array.from(planMap.values()).map((plan) => ({
					...plan,
					user_plan: 2
				}));

				// 4. 合并结果
				let newMenus = [...unmatchedPlansToPrepend, ...matchedMenus];

				// 5. 去重：按id分组，每组保留user_plan最大的项
				const uniqueMenusMap = new Map();
				newMenus.forEach((menu) => {
					const existing = uniqueMenusMap.get(menu.id);
					if (!existing || menu.user_plan > existing.user_plan) {
						uniqueMenusMap.set(menu.id, menu);
					}
				});

				// 6. 转换回数组并替换原menus
				menus = Array.from(uniqueMenusMap.values());

				// console.log('新的菜单', menus);
			}
		} catch (err) {
			console.error(err);
		}
	};

	const menuList = async () => {
		try {
			const res = await getUsers(localStorage.token).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				menus = res.plans ?? [];
				usermenu();
			}
		} catch (err) {
			console.error(err);
		}
	};

	onMount(async () => {
		console.log('用户', $user);

		loaded = true;
		menuList();
	});

	const nihasd = async () => {
		try {
			const res = await subscriptionprocess(localStorage.token).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				console.log('订单', res);
			}
		} catch (err) {
			console.error(err);
		}
	};
</script>

<ConfirmDialog bind:show={showDeleteConfirmDialog} menu={frmoMenu} on:confirm={() => {}} />
<PaymentDialog
	bind:show={showPaymentDialog}
	on:confirm={() => {
		showPaymentDialog = false;
	}}
/>
<div class="flex flex-col items-center w-full min-h-screen bg-white p-8">
	<!-- 顶部标题和切换 -->
	<div class="text-center mb-6 flex flex-col items-center">
		<div class="text-4xl font-extrabold mb-2 text-black">{$i18n.t('Upgrade Package')}</div>
		<div class="text-base text-gray-500 mb-3">
			{$i18n.t('Get more points to improve efficiency')}
		</div>
		<div class="flex justify-center gap-4 mb-4">
			<button
				type="button"
				class="text-blue-600 cursor-pointer text-sm hover:underline bg-transparent border-none p-0"
				on:click={() => {
					showPaymentDialog = true;
				}}
			>
				<span class="flex items-center gap-1">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
						><g
							fill="none"
							stroke="currentColor"
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="1.5"
							><ellipse cx="15.5" cy="11" rx="6.5" ry="2" /><path
								d="M22 15.5c0 1.105-2.91 2-6.5 2s-6.5-.895-6.5-2"
							/><path d="M22 11v8.8c0 1.215-2.91 2.2-6.5 2.2S9 21.015 9 19.8V11" /><ellipse
								cx="8.5"
								cy="4"
								rx="6.5"
								ry="2"
							/><path d="M6 11c-1.892-.23-3.63-.825-4-2m4 7c-1.892-.23-3.63-.825-4-2" /><path
								d="M6 21c-1.892-.23-3.63-.826-4-2V4m13 2V4"
							/></g
						></svg
					>
					{$i18n.t('exchangecode-title')}
				</span>
			</button>
			<button
				type="button"
				class="text-blue-600 cursor-pointer text-sm hover:underline bg-transparent border-none p-0"
				on:click={() => {
					menuList();
				}}
			>
				<span class="flex items-center gap-1">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
						><path
							fill="currentColor"
							d="M12 20q-3.35 0-5.675-2.325T4 12t2.325-5.675T12 4q1.725 0 3.3.712T18 6.75V5q0-.425.288-.712T19 4t.713.288T20 5v5q0 .425-.288.713T19 11h-5q-.425 0-.712-.288T13 10t.288-.712T14 9h3.2q-.8-1.4-2.187-2.2T12 6Q9.5 6 7.75 7.75T6 12t1.75 4.25T12 18q1.7 0 3.113-.862t2.187-2.313q.2-.35.563-.487t.737-.013q.4.125.575.525t-.025.75q-1.025 2-2.925 3.2T12 20"
						/></svg
					>

					{$i18n.t('refresh-menu-info')}
				</span>
			</button>
		</div>
		<div
			class="flex justify-center mb-2 p-1 w-[150px] rounded-full order border-gray-200 bg-gray-100 text-gray-500"
		>
			<button
				class="px-2 flex-1 py-1.5 rounded-full border border-gray-200 bg-white text-black font-medium shadow-sm focus:outline-none"
				>{$i18n.t('Personal')}</button
			>
			<button class="px-2 flex-1 py-1.5 rounded-full text-gray-500 font-medium"
				>{$i18n.t('Enterprise')}</button
			>
		</div>
		<div class="text-xs text-gray-400 mt-2">
			* {$i18n.t('Use two fingers to slide left and right or hold Shift to scroll more')} *
		</div>
	</div>

	<!-- 套餐卡片 -->
	<div class="max-w-6xl w-full overflow-auto mx-auto">
		<div class="relative">
			<!-- 修复：移除重复的class属性，修正CSS类名 -->
			<div
				class="flex flex-nowrap overflow-x-auto scrollbar-none snap-x snap-mandatory gap-4 pb-5 px-1 md:justify-center"
			>
				{#each menus.filter((menu) => menu.is_active) as menu (menu.id)}
					<div class="flex-shrink-0 w-[300px] snap-center svelte-du15c4">
						<div
							class="relative bg-white rounded-2xl p-8 flex-1 min-w-[260px] max-w-[280px] flex flex-col items-start border border-gray-200 shadow-md
						 border border-gray-200 dark:border-gray-800 rounded-xl p-6 h-full flex flex-col relative hover:shadow-lg transition-all duration-300"
						>
							<div class="w-full">
								{#if menu.user_plan > 0}
									<div
										class={menu.user_plan === 1
											? 'absolute top-4 right-4 text-xs px-3 py-0.5 rounded-full text-white bg-green-500'
											: 'absolute top-4 right-4 text-xs px-3 py-0.5 rounded-full text-white bg-[#155DFC]'}
									>
										当前套餐
									</div>
								{/if}

								<div class="text-xl font-bold mb-2 text-black">{menu.name}</div>
								<div class="text-3xl font-extrabold mb-1 text-black">
									${menu.price}
									<span class="text-base font-normal text-gray-500">/ {menu.duration}天</span>
								</div>
								<div class="text-xl font-bold mb-2 text-black">{menu.credits}V豆</div>

								<div class="text-gray-500 text-sm mb-4 max-h-[280px] overflow-auto">
									{menu.description}
								</div>
							</div>
							<div class="flex-1 w-full flex flex-col justify-end">
								{#if menu.user_plan === 0}
									<button
										class="w-full h-10 bg-[#333333] text-white py-2 rounded font-bold flex items-center justify-center gap-2"
										on:click={() => {
											console.log('购买', menu);
											frmoMenu = menu; // 修正：将frmoMenu改为fromMenu
											showDeleteConfirmDialog = true;
										}}
									>
										<span class="mr-1">⟳</span> 购买
									</button>
								{:else if menu.user_plan === 1}
									<div class="text-xs text-gray-400 mb-2">当前使用中</div>
									<button
										class="w-full h-10 bg-green-500 text-white py-2 rounded font-bold flex items-center justify-center gap-2"
										on:click={() => {
											console.log('续费', menu);
											frmoMenu = menu; // 修正：将frmoMenu改为fromMenu
											showDeleteConfirmDialog = true;
										}}
									>
										<span class="mr-1">⟳</span> 续费
									</button>
								{:else}
									<div class="text-xs text-[#155DFC] mb-2">当前使用中</div>
									<button
										class="w-full h-10 bg-[#155DFC] text-white py-2 rounded font-bold flex items-center justify-center gap-2"
										on:click={() => {
											console.log('联系管理员续费', menu);
											frmoMenu = menu; // 添加：确保fromMenu被赋值
											showDeleteConfirmDialog = true; // 添加：触发确认对话框
										}}
									>
										<span class="mr-1">⟳</span> 联系管理员续费
									</button>
								{/if}
							</div>
						</div>
					</div>
				{/each}
			</div>
		</div>
	</div>
</div>
